//! Candidate indexes preserve the separately defined resource specificity order.
use std::collections::BTreeMap;

use crate::resource::IpResource;

#[derive(Clone, Debug)]
pub(crate) struct IpNode {
    index: usize,
    start: u32,
    end: u32,
    max_end: u32,
    left: Option<Box<IpNode>>,
    right: Option<Box<IpNode>>,
}

impl IpNode {
    pub fn build(resources: &[IpResource]) -> Option<Box<Self>> {
        let mut indices: Vec<_> = (0..resources.len()).collect();
        indices.sort_by_key(|&i| u32::from(resources[i].ip_min));
        Self::from_sorted(&indices, resources)
    }

    fn from_sorted(indices: &[usize], resources: &[IpResource]) -> Option<Box<Self>> {
        if indices.is_empty() {
            return None;
        }
        let mid = indices.len() / 2;
        let index = indices[mid];
        let left = Self::from_sorted(&indices[..mid], resources);
        let right = Self::from_sorted(&indices[mid + 1..], resources);
        let start = u32::from(resources[index].ip_min);
        let end = u32::from(resources[index].ip_max);
        let max_end = end
            .max(left.as_ref().map_or(0, |n| n.max_end))
            .max(right.as_ref().map_or(0, |n| n.max_end));
        Some(Box::new(Self {
            index,
            start,
            end,
            max_end,
            left,
            right,
        }))
    }

    pub fn find(&self, ip: u32, accept: &impl Fn(usize) -> bool, best: &mut Option<usize>) {
        if ip > self.max_end {
            return;
        }
        if let Some(left) = &self.left {
            left.find(ip, accept, best);
        }
        if self.start <= ip
            && ip <= self.end
            && best.is_none_or(|i| self.index < i)
            && accept(self.index)
        {
            *best = Some(self.index);
        }
        if self.start <= ip
            && let Some(right) = &self.right
        {
            right.find(ip, accept, best);
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DomainNode {
    children: BTreeMap<u8, DomainNode>,
    entries: Vec<usize>,
}

impl DomainNode {
    pub fn insert(&mut self, suffix: &str, index: usize) {
        let mut node = self;
        for byte in suffix.bytes().rev() {
            node = node.children.entry(byte).or_default();
        }
        node.entries.push(index);
    }

    pub fn find(&self, host: &str, accept: impl Fn(usize) -> bool) -> Option<usize> {
        let mut node = self;
        let mut best = None;
        let mut bytes = host.bytes().rev();
        loop {
            for &index in &node.entries {
                if best.is_none_or(|i| index < i) && accept(index) {
                    best = Some(index);
                }
            }
            let Some(next) = bytes.next().and_then(|byte| node.children.get(&byte)) else {
                break;
            };
            node = next;
        }
        best
    }
}
