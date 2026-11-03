use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::Instant;

#[derive(Debug)]
struct Binding {
    host: String,
    epoch: u64,
    generation: u64,
    until: Instant,
}

/// Fake addresses are never reassigned during this pool's lifetime, even after
/// TTL expiry. An application retaining an old IP cannot reach a different host.
#[derive(Debug)]
pub struct FakeIpPool {
    fake: HashMap<Ipv4Addr, Binding>,
    real: HashMap<Ipv4Addr, Vec<Binding>>,
    next: u32,
    capacity: usize,
}
impl FakeIpPool {
    pub fn new(capacity: usize) -> Self {
        Self {
            fake: HashMap::new(),
            real: HashMap::new(),
            next: 1,
            capacity,
        }
    }
    pub fn is_fake(ip: Ipv4Addr) -> bool {
        u32::from(ip) & 0xfffe0000 == u32::from(Ipv4Addr::new(198, 18, 0, 0))
    }
    fn prune(&mut self, epoch: u64, generation: u64) {
        let valid = |b: &Binding| {
            b.epoch == epoch && b.generation == generation && b.until > Instant::now()
        };
        self.fake.retain(|_, b| valid(b));
        self.real.retain(|_, values| {
            values.retain(&valid);
            !values.is_empty()
        });
    }
    pub fn assign(
        &mut self,
        host: &str,
        epoch: u64,
        generation: u64,
        ttl: Duration,
    ) -> io::Result<Ipv4Addr> {
        self.prune(epoch, generation);
        if let Some((&ip, binding)) = self.fake.iter_mut().find(|(_, b)| b.host == host) {
            binding.until = Instant::now() + ttl;
            return Ok(ip);
        }
        if self.fake.len() + self.real.len() >= self.capacity || self.next >= 131071 {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "Fake IP pool is exhausted",
            ));
        }
        let ip = Ipv4Addr::from(u32::from(Ipv4Addr::new(198, 18, 0, 0)) + self.next);
        self.next += 1;
        self.fake.insert(
            ip,
            Binding {
                host: host.to_owned(),
                epoch,
                generation,
                until: Instant::now() + ttl,
            },
        );
        Ok(ip)
    }
    pub fn lookup(&mut self, ip: Ipv4Addr, epoch: u64, generation: u64) -> Option<String> {
        self.prune(epoch, generation);
        self.fake.get(&ip).map(|b| b.host.clone())
    }
    pub fn remember_real(
        &mut self,
        ip: Ipv4Addr,
        host: &str,
        epoch: u64,
        generation: u64,
        ttl: Duration,
    ) -> io::Result<()> {
        self.prune(epoch, generation);
        if !self.real.contains_key(&ip) && self.fake.len() + self.real.len() >= self.capacity {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "DNS identity pool is exhausted",
            ));
        }
        let bindings = self.real.entry(ip).or_default();
        if let Some(binding) = bindings.iter_mut().find(|b| b.host == host) {
            binding.until = Instant::now() + ttl;
            return Ok(());
        }
        if bindings.len() >= 16 {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "too many domains share this address",
            ));
        }
        bindings.push(Binding {
            host: host.into(),
            epoch,
            generation,
            until: Instant::now() + ttl,
        });
        Ok(())
    }
    pub fn real_hosts(&mut self, ip: Ipv4Addr, epoch: u64, generation: u64) -> Vec<String> {
        self.prune(epoch, generation);
        self.real
            .get(&ip)
            .map(|values| values.iter().map(|b| b.host.clone()).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn expiry_and_policy_changes_revoke_names_without_reassigning_ips() {
        let mut pool = FakeIpPool::new(1);
        let ttl = Duration::from_secs(60);
        let old = pool.assign("a.test", 1, 1, ttl).unwrap();
        assert_eq!(pool.lookup(old, 1, 1).as_deref(), Some("a.test"));
        assert!(pool.assign("b.test", 1, 1, ttl).is_err());
        tokio::time::advance(ttl).await;
        assert!(pool.lookup(old, 1, 1).is_none());
        let new = pool.assign("b.test", 1, 1, ttl).unwrap();
        assert_ne!(old, new);
        assert!(pool.lookup(new, 2, 1).is_none());
        let new = pool.assign("b.test", 2, 1, ttl).unwrap();
        assert!(pool.lookup(new, 2, 2).is_none());
    }
}
