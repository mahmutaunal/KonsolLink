//! Write-ahead recovery for fixed settings and an optional scoped PF gateway.
use serde::{Deserialize, Serialize};
use std::io;
use thiserror::Error;

use crate::engine::{EnginePlan, EngineRecord, EngineStep, ProcessIdentity};

mod store;
#[cfg(target_os = "macos")]
pub(crate) use store::verify_socket_ancestor;
pub use store::Store;

#[derive(Debug, Error)]
pub enum Error {
    #[error("journal I/O: {0}")]
    Io(#[from] io::Error),
    #[error("journal data: {0}")]
    Data(#[from] serde_json::Error),
    #[error("unsafe journal storage: {0}")]
    Unsafe(&'static str),
    #[error("helper already owns the journal lock")]
    Locked,
    #[error("invalid journal: {0}")]
    Invalid(&'static str),
    #[error("unfinished transaction requires recovery")]
    RecoveryRequired,
    #[error("journal write failed; reopen and recover before continuing")]
    Poisoned,
    #[error("setting changed outside this transaction: {0:?}")]
    Conflict(Setting),
    #[error("backend: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A closed allowlist, never arbitrary sysctl names or shell commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Setting {
    Ipv4Forwarding,
    Ipv6Forwarding,
    IcmpRedirects,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Prepared,
    Applying,
    Active,
    RollingBack,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Pending,
    Intent,
    Applied,
    Restored,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub setting: Setting,
    pub before: u32,
    pub after: u32,
    pub step: Step,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub schema_version: u32,
    pub generation: u64,
    pub phase: Phase,
    pub changes: Vec<Change>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<crate::gateway::Plan>,
    #[serde(default)]
    pub gateway_step: GatewayStep,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<EngineRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interception: Option<InterceptionRecord>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayStep {
    #[default]
    Pending,
    Intent,
    Applied,
    Restored,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterceptionRecord {
    pub plan: crate::interception::Plan,
    pub step: InterceptionStep,
    #[serde(default = "existing_pf_default")]
    pub pf_was_enabled: bool,
    #[serde(default = "applied_step_default")]
    pub pf_step: Step,
}

fn existing_pf_default() -> bool {
    true
}

fn applied_step_default() -> Step {
    Step::Applied
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptionStep {
    #[default]
    Pending,
    Intent,
    Applied,
    Restored,
}

impl Journal {
    fn validate(&self) -> Result<()> {
        if !(1..=3).contains(&self.schema_version)
            || self.generation == 0
            || self.changes.len() > 3
            || (self.schema_version == 1 && self.engine.is_some())
            || (self.schema_version < 3 && self.interception.is_some())
        {
            return Err(Error::Invalid("version, generation or operation count"));
        }
        for (i, change) in self.changes.iter().enumerate() {
            if change.before > 1
                || change.after > 1
                || change.before == change.after
                || self.changes[..i]
                    .iter()
                    .any(|c| c.setting == change.setting)
            {
                return Err(Error::Invalid("setting values or duplicate operation"));
            }
        }
        if let Some(plan) = &self.gateway {
            plan.validate()
                .map_err(|_| Error::Invalid("gateway plan"))?;
            if (self.phase == Phase::Prepared && self.gateway_step != GatewayStep::Pending)
                || (self.phase == Phase::Active && self.gateway_step != GatewayStep::Applied)
                || (self.phase == Phase::Complete && self.gateway_step != GatewayStep::Restored)
                || (self.phase == Phase::Applying && self.gateway_step == GatewayStep::Restored)
                || (self.phase == Phase::Applying
                    && self.gateway_step != GatewayStep::Applied
                    && self.changes.iter().any(|c| c.step != Step::Pending))
            {
                return Err(Error::Invalid("gateway step ordering"));
            }
        } else if self.gateway_step != GatewayStep::Pending {
            return Err(Error::Invalid("gateway step without plan"));
        }
        if let Some(engine) = &self.engine {
            if self.phase == Phase::Complete && engine.step == EngineStep::Restored {
                if engine.plan.loopback_port != crate::engine::LOOPBACK_PORT
                    || engine.plan.artifact_sha256.len() != 64
                    || !engine
                        .plan
                        .artifact_sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                    || engine
                        .process
                        .is_some_and(|process| process.validate().is_err())
                {
                    return Err(Error::Invalid("historical engine record"));
                }
            } else {
                engine.validate()?;
            }
            if self.gateway.is_none()
                || matches!(self.phase, Phase::Prepared | Phase::Applying)
                || (self.phase == Phase::Complete && engine.step != EngineStep::Restored)
            {
                return Err(Error::Invalid("engine phase ordering"));
            }
        }
        if let Some(interception) = &self.interception {
            interception.plan.validate()?;
            let gateway = self
                .gateway
                .as_ref()
                .ok_or(Error::Invalid("interception without gateway"))?;
            let engine = self
                .engine
                .as_ref()
                .ok_or(Error::Invalid("interception without engine"))?;
            if !interception.plan.matches_gateway(gateway)
                || matches!(self.phase, Phase::Prepared | Phase::Applying)
                || (self.phase == Phase::Active
                    && interception.step != InterceptionStep::Restored
                    && engine.step != EngineStep::Applied)
                || (self.phase == Phase::Complete
                    && interception.step != InterceptionStep::Restored)
                || (self.phase != Phase::RollingBack
                    && engine.step == EngineStep::Restored
                    && interception.step != InterceptionStep::Restored)
            {
                return Err(Error::Invalid("interception ordering"));
            }
        }
        let steps: Vec<_> = self.changes.iter().map(|c| c.step).collect();
        let apply_order = |steps: &[Step]| {
            let rest = steps
                .iter()
                .skip_while(|s| **s == Step::Applied)
                .copied()
                .collect::<Vec<_>>();
            let rest = if rest.first() == Some(&Step::Intent) {
                &rest[1..]
            } else {
                &rest[..]
            };
            rest.iter().all(|s| *s == Step::Pending)
        };
        let valid = match self.phase {
            Phase::Prepared => steps.iter().all(|s| *s == Step::Pending),
            Phase::Applying => apply_order(&steps),
            Phase::Active => steps.iter().all(|s| *s == Step::Applied),
            Phase::Complete => steps.iter().all(|s| *s == Step::Restored),
            Phase::RollingBack => {
                // Independent restores can finish even if an earlier restore
                // failed. Unrestored operations retain their application order.
                let remaining: Vec<_> = steps
                    .iter()
                    .copied()
                    .filter(|step| *step != Step::Restored)
                    .collect();
                apply_order(&remaining)
            }
        };
        if !valid {
            return Err(Error::Invalid("phase/step ordering"));
        }
        Ok(())
    }
}

/// Implementations must enforce their own capability/ownership gates. Reads
/// return observed values; writes must finish synchronously or return an error.
/// Gateway operations must be idempotent and restricted to the journal plan.
pub trait SettingsBackend {
    fn read(&mut self, setting: Setting) -> Result<u32>;
    fn write(&mut self, setting: Setting, value: u32) -> Result<()>;
    fn gateway(&mut self, _plan: &crate::gateway::Plan, _enable: bool) -> Result<()> {
        Err(Error::Backend("gateway backend unavailable".into()))
    }
    fn same_boot(&mut self, _plan: &crate::gateway::Plan) -> Result<bool> {
        Err(Error::Backend("boot identity unavailable".into()))
    }
    fn stop_engine(&mut self, _record: &EngineRecord) -> Result<()> {
        Err(Error::Backend(
            "engine lifecycle backend unavailable".into(),
        ))
    }
    fn interception(&mut self, _plan: &crate::interception::Plan, _enable: bool) -> Result<()> {
        Err(Error::Backend("interception backend unavailable".into()))
    }
    fn interception_health(&mut self, _plan: &crate::interception::Plan) -> Result<()> {
        Err(Error::Backend(
            "interception health backend unavailable".into(),
        ))
    }
    /// Existing test/platform backends predate M2 PF ownership and model PF as
    /// already active. macOS overrides both methods with kernel state.
    fn packet_filter_enabled(&mut self) -> Result<bool> {
        Ok(true)
    }
    fn packet_filter(&mut self, _enable: bool) -> Result<()> {
        Err(Error::Backend("packet-filter lifecycle unavailable".into()))
    }
}

impl Store {
    /// Snapshot and journal the full plan before any side effect. Caller owns
    /// the Store lock throughout. A previous incomplete journal blocks start.
    pub fn prepare(
        &mut self,
        backend: &mut impl SettingsBackend,
        desired: &[(Setting, u32)],
    ) -> Result<()> {
        self.prepare_inner(backend, desired, None)
    }

    pub fn prepare_gateway(
        &mut self,
        backend: &mut impl SettingsBackend,
        plan: crate::gateway::Plan,
    ) -> Result<()> {
        plan.validate().map_err(Error::Backend)?;
        if backend.read(Setting::Ipv4Forwarding)? != 0
            || backend.read(Setting::Ipv6Forwarding)? != 0
        {
            return Err(Error::Backend(
                "forwarding changed before transaction snapshot".into(),
            ));
        }
        let desired: &[(Setting, u32)] = if plan.mode == crate::gateway::Mode::Userspace {
            &[]
        } else {
            &[(Setting::IcmpRedirects, 0), (Setting::Ipv4Forwarding, 1)]
        };
        self.prepare_inner(backend, desired, Some(plan))
    }

    fn prepare_inner(
        &mut self,
        backend: &mut impl SettingsBackend,
        desired: &[(Setting, u32)],
        gateway: Option<crate::gateway::Plan>,
    ) -> Result<()> {
        let previous = self.load()?;
        if previous
            .as_ref()
            .is_some_and(|j| j.phase != Phase::Complete)
        {
            return Err(Error::RecoveryRequired);
        }
        if desired.len() > 3
            || desired
                .iter()
                .enumerate()
                .any(|(i, (key, value))| *value > 1 || desired[..i].iter().any(|(k, _)| k == key))
        {
            return Err(Error::Invalid("invalid desired settings"));
        }
        let mut changes = Vec::new();
        for &(setting, after) in desired {
            let before = backend.read(setting)?;
            if gateway.is_some() && setting == Setting::Ipv4Forwarding && before != 0 {
                return Err(Error::Conflict(setting));
            }
            if before > 1 {
                return Err(Error::Conflict(setting));
            }
            if before != after {
                changes.push(Change {
                    setting,
                    before,
                    after,
                    step: Step::Pending,
                });
            }
        }
        let generation = previous
            .map_or(Some(1), |j| j.generation.checked_add(1))
            .ok_or(Error::Invalid("generation overflow"))?;
        self.save(&Journal {
            schema_version: 2,
            generation,
            phase: Phase::Prepared,
            changes,
            gateway,
            gateway_step: GatewayStep::Pending,
            engine: None,
            interception: None,
        })
    }

    pub fn prepare_engine(&mut self, plan: EnginePlan) -> Result<()> {
        plan.validate()?;
        let mut journal = self
            .load()?
            .ok_or(Error::Invalid("missing active journal"))?;
        if journal.phase != Phase::Active
            || journal.gateway.is_none()
            || journal.gateway_step != GatewayStep::Applied
            || journal.engine.is_some()
        {
            return Err(Error::RecoveryRequired);
        }
        journal.schema_version = 2;
        journal.engine = Some(EngineRecord {
            plan,
            process: None,
            step: EngineStep::Pending,
        });
        self.save(&journal)
    }

    pub fn prepare_interception(
        &mut self,
        backend: &mut impl SettingsBackend,
        plan: crate::interception::Plan,
    ) -> Result<()> {
        plan.validate()?;
        let mut journal = self
            .load()?
            .ok_or(Error::Invalid("missing active journal"))?;
        let engine = journal
            .engine
            .as_ref()
            .ok_or(Error::Invalid("missing engine"))?;
        let gateway = journal
            .gateway
            .as_ref()
            .ok_or(Error::Invalid("missing gateway"))?;
        if journal.phase != Phase::Active
            || engine.step != EngineStep::Applied
            || journal.interception.is_some()
            || !plan.matches_gateway(gateway)
        {
            return Err(Error::RecoveryRequired);
        }
        let pf_was_enabled = backend.packet_filter_enabled()?;
        journal.schema_version = 3;
        journal.interception = Some(InterceptionRecord {
            plan,
            step: InterceptionStep::Pending,
            pf_was_enabled,
            pf_step: if pf_was_enabled {
                Step::Applied
            } else {
                Step::Pending
            },
        });
        self.save(&journal)
    }

    pub fn apply_interception(
        &mut self,
        backend: &mut impl SettingsBackend,
        now_secs: u64,
    ) -> Result<()> {
        let mut journal = self
            .load()?
            .ok_or(Error::Invalid("missing active journal"))?;
        let interception = journal
            .interception
            .as_ref()
            .ok_or(Error::Invalid("missing interception plan"))?;
        if journal.phase != Phase::Active
            || interception.step != InterceptionStep::Pending
            || !interception.plan.is_current(now_secs)
        {
            return Err(Error::RecoveryRequired);
        }
        let start_pf = !interception.pf_was_enabled;
        if start_pf {
            journal
                .interception
                .as_mut()
                .expect("present above")
                .pf_step = Step::Intent;
            self.save(&journal)?;
            backend.packet_filter(true)?;
            if !backend.packet_filter_enabled()? {
                return Err(Error::Backend("packet filter did not start".into()));
            }
            journal
                .interception
                .as_mut()
                .expect("present above")
                .pf_step = Step::Applied;
            self.save(&journal)?;
        }
        journal.interception.as_mut().expect("present above").step = InterceptionStep::Intent;
        self.save(&journal)?;
        let plan = &journal.interception.as_ref().expect("present above").plan;
        backend.interception(plan, true)?;
        journal.interception.as_mut().expect("present above").step = InterceptionStep::Applied;
        self.save(&journal)
    }

    /// Replace an applied rule set under the same owned anchor. Durable intent
    /// precedes the atomic PF transaction; rollback can flush the anchor in
    /// either the old-rules or new-rules crash window.
    pub fn replace_interception(
        &mut self,
        backend: &mut impl SettingsBackend,
        plan: crate::interception::Plan,
        now_secs: u64,
    ) -> Result<()> {
        plan.validate()?;
        if !plan.is_current(now_secs) {
            return Err(Error::Invalid("expired interception plan"));
        }
        let mut journal = self
            .load()?
            .ok_or(Error::Invalid("missing active journal"))?;
        let gateway = journal
            .gateway
            .as_ref()
            .ok_or(Error::Invalid("missing gateway"))?;
        let engine = journal
            .engine
            .as_ref()
            .ok_or(Error::Invalid("missing engine"))?;
        let current = journal
            .interception
            .as_ref()
            .ok_or(Error::Invalid("missing interception"))?;
        if journal.phase != Phase::Active
            || engine.step != EngineStep::Applied
            || current.step != InterceptionStep::Applied
            || !plan.matches_gateway(gateway)
            || current.plan.anchor != plan.anchor
        {
            return Err(Error::RecoveryRequired);
        }
        let pf_was_enabled = current.pf_was_enabled;
        let pf_step = current.pf_step;
        journal.interception = Some(InterceptionRecord {
            plan,
            step: InterceptionStep::Intent,
            pf_was_enabled,
            pf_step,
        });
        self.save(&journal)?;
        let plan = &journal.interception.as_ref().expect("set above").plan;
        backend.interception(plan, true)?;
        backend.interception_health(plan)?;
        journal.interception.as_mut().expect("set above").step = InterceptionStep::Applied;
        self.save(&journal)
    }

    /// Extend only authority metadata when the exact kernel rule set is
    /// unchanged. No external mutation occurs.
    pub fn renew_interception(
        &mut self,
        plan: crate::interception::Plan,
        now_secs: u64,
    ) -> Result<()> {
        plan.validate()?;
        if !plan.is_current(now_secs) {
            return Err(Error::Invalid("expired interception plan"));
        }
        let mut journal = self
            .load()?
            .ok_or(Error::Invalid("missing active journal"))?;
        let current = journal
            .interception
            .as_ref()
            .ok_or(Error::Invalid("missing interception"))?;
        if journal.phase != Phase::Active
            || current.step != InterceptionStep::Applied
            || !current.plan.same_kernel_rules(&plan)
        {
            return Err(Error::RecoveryRequired);
        }
        journal.interception.as_mut().expect("present above").plan = plan;
        self.save(&journal)
    }

    /// Stop only the M2 layer while keeping the active gateway transaction.
    /// Restored records are durably saved before their slots are cleared so a
    /// restart can attach a fresh engine to the same observation session.
    pub fn stop_m2(&mut self, backend: &mut impl SettingsBackend) -> Result<()> {
        let mut journal = self
            .load()?
            .ok_or(Error::Invalid("missing active journal"))?;
        if journal.phase != Phase::Active {
            return Err(Error::RecoveryRequired);
        }
        let same_boot = match &journal.gateway {
            Some(plan) => backend.same_boot(plan)?,
            None => false,
        };
        if !same_boot {
            return Err(Error::RecoveryRequired);
        }
        if let Some(interception) = &journal.interception {
            if matches!(
                interception.step,
                InterceptionStep::Intent | InterceptionStep::Applied
            ) {
                backend.interception(&interception.plan, false)?;
            }
            journal
                .interception
                .as_mut()
                .expect("interception exists")
                .step = InterceptionStep::Restored;
            self.save(&journal)?;
            let interception = journal.interception.as_ref().expect("interception exists");
            if !interception.pf_was_enabled
                && matches!(interception.pf_step, Step::Intent | Step::Applied)
            {
                if backend.packet_filter_enabled()? {
                    backend.packet_filter(false)?;
                }
                if backend.packet_filter_enabled()? {
                    return Err(Error::Backend("packet filter did not stop".into()));
                }
                journal
                    .interception
                    .as_mut()
                    .expect("interception exists")
                    .pf_step = Step::Restored;
                self.save(&journal)?;
            }
        }
        if let Some(engine) = &journal.engine {
            if matches!(engine.step, EngineStep::Intent | EngineStep::Applied) {
                backend.stop_engine(engine)?;
            }
            journal.engine.as_mut().expect("engine exists").step = EngineStep::Restored;
            self.save(&journal)?;
        }
        journal.interception = None;
        journal.engine = None;
        self.save(&journal)
    }

    pub fn mark_engine_spawned(&mut self, process: ProcessIdentity) -> Result<()> {
        process.validate()?;
        let mut journal = self
            .load()?
            .ok_or(Error::Invalid("missing active journal"))?;
        let engine = journal
            .engine
            .as_mut()
            .ok_or(Error::Invalid("missing engine plan"))?;
        if journal.phase != Phase::Active
            || engine.step != EngineStep::Pending
            || engine.process.is_some()
        {
            return Err(Error::Invalid("engine spawn ordering"));
        }
        engine.process = Some(process);
        engine.step = EngineStep::Intent;
        self.save(&journal)
    }

    pub fn mark_engine_started(&mut self) -> Result<()> {
        let mut journal = self
            .load()?
            .ok_or(Error::Invalid("missing active journal"))?;
        let engine = journal
            .engine
            .as_mut()
            .ok_or(Error::Invalid("missing engine plan"))?;
        if journal.phase != Phase::Active
            || engine.step != EngineStep::Intent
            || engine.process.is_none()
        {
            return Err(Error::Invalid("engine start ordering"));
        }
        engine.step = EngineStep::Applied;
        self.save(&journal)
    }

    /// Any error leaves recovery evidence. Call rollback (or reopen on a journal
    /// persistence failure); never start another transaction after an error.
    pub fn apply(&mut self, backend: &mut impl SettingsBackend) -> Result<()> {
        let mut journal = self
            .load()?
            .ok_or(Error::Invalid("missing prepared journal"))?;
        if journal.phase != Phase::Prepared {
            return Err(Error::RecoveryRequired);
        }
        journal.phase = Phase::Applying;
        self.save(&journal)?;
        if let Some(plan) = &journal.gateway {
            if !backend.same_boot(plan)? {
                return Err(Error::RecoveryRequired);
            }
            journal.gateway_step = GatewayStep::Intent;
            self.save(&journal)?;
            backend.gateway(plan, true)?;
            journal.gateway_step = GatewayStep::Applied;
            self.save(&journal)?;
        }
        for i in 0..journal.changes.len() {
            let change = &journal.changes[i];
            if backend.read(change.setting)? != change.before {
                return Err(Error::Conflict(change.setting));
            }
            journal.changes[i].step = Step::Intent;
            self.save(&journal)?; // Durable intent MUST precede write.
            let change = &journal.changes[i];
            backend.write(change.setting, change.after)?;
            if backend.read(change.setting)? != change.after {
                return Err(Error::Conflict(change.setting));
            }
            journal.changes[i].step = Step::Applied;
            self.save(&journal)?;
        }
        journal.phase = Phase::Active;
        self.save(&journal)
    }

    /// Reverse-order, idempotent recovery handles the crash window between a
    /// write and its Applied marker. Unexpected values are never overwritten.
    pub fn rollback(&mut self, backend: &mut impl SettingsBackend) -> Result<()> {
        let Some(mut journal) = self.load()? else {
            return Ok(());
        };
        if journal.phase == Phase::Complete {
            return Ok(());
        }
        let same_boot = match &journal.gateway {
            Some(plan) => backend.same_boot(plan)?,
            None => true,
        };
        journal.phase = Phase::RollingBack;
        let mut errors = Vec::new();
        // A failed operation retains its durable step. Continue independent
        // cleanup, then leave the journal recoverable rather than claiming OFF.
        macro_rules! persist {
            () => {
                if let Err(error) = self.save(&journal) {
                    errors.push(error);
                }
            };
        }
        persist!();
        if let Some(record) = journal.interception.clone() {
            let remove = if same_boot
                && matches!(
                    record.step,
                    InterceptionStep::Intent | InterceptionStep::Applied
                ) {
                backend.interception(&record.plan, false)
            } else {
                Ok(())
            };
            match remove {
                Ok(()) => {
                    journal.interception.as_mut().unwrap().step = InterceptionStep::Restored;
                    persist!();
                }
                Err(error) => errors.push(error),
            }
            if !record.pf_was_enabled {
                let restore = (|| -> Result<()> {
                    if same_boot && matches!(record.pf_step, Step::Intent | Step::Applied) {
                        if backend.packet_filter_enabled()? {
                            backend.packet_filter(false)?;
                        }
                        if backend.packet_filter_enabled()? {
                            return Err(Error::Backend("packet filter did not stop".into()));
                        }
                    }
                    Ok(())
                })();
                match restore {
                    Ok(()) => {
                        journal.interception.as_mut().unwrap().pf_step = Step::Restored;
                        persist!();
                    }
                    Err(error) => errors.push(error),
                }
            }
        }
        if let Some(record) = journal.engine.clone() {
            let stop =
                if same_boot && matches!(record.step, EngineStep::Intent | EngineStep::Applied) {
                    backend.stop_engine(&record)
                } else {
                    Ok(())
                };
            match stop {
                Ok(()) => {
                    journal.engine.as_mut().unwrap().step = EngineStep::Restored;
                    persist!();
                }
                Err(error) => errors.push(error),
            }
        }
        // Forwarding must not be restored while an owned engine is still live.
        // Preserve this dependency while allowing unrelated cleanup above.
        if journal
            .engine
            .as_ref()
            .is_some_and(|record| record.step != EngineStep::Restored)
        {
            return Err(errors.into_iter().next().unwrap_or(Error::RecoveryRequired));
        }
        for i in (0..journal.changes.len()).rev() {
            let change = &journal.changes[i];
            if change.step == Step::Restored {
                continue;
            }
            let restore = (|| -> Result<()> {
                if same_boot && change.step != Step::Pending {
                    let current = backend.read(change.setting)?;
                    if current == change.after {
                        backend.write(change.setting, change.before)?;
                        if backend.read(change.setting)? != change.before {
                            return Err(Error::Conflict(change.setting));
                        }
                    } else if current != change.before {
                        return Err(Error::Conflict(change.setting));
                    }
                }
                Ok(())
            })();
            match restore {
                Ok(()) => {
                    journal.changes[i].step = Step::Restored;
                    persist!();
                }
                Err(error) => errors.push(error),
            }
        }
        if let Some(plan) = &journal.gateway {
            let remove = if same_boot
                && matches!(
                    journal.gateway_step,
                    GatewayStep::Intent | GatewayStep::Applied
                ) {
                backend.gateway(plan, false)
            } else {
                Ok(())
            };
            match remove {
                Ok(()) => {
                    journal.gateway_step = GatewayStep::Restored;
                    persist!();
                }
                Err(error) => errors.push(error),
            }
        }
        if !errors.is_empty() {
            for error in &errors {
                eprintln!("KonsolLink recovery: {error}");
            }
            return Err(errors.remove(0));
        }
        journal.phase = Phase::Complete;
        self.save(&journal)
    }
}

#[cfg(test)]
mod tests;
