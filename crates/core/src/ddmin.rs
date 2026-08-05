//! Delta debugging (ddmin) for minimal failure-inducing change sets.

/// Predicate: true if the subset still fails.
pub trait FailsPredicate {
    fn fails(&self, subset: &[usize]) -> bool;
}

/// Classic ddmin over indices into a change set.
/// Returns the smallest subset of indices that still fails, or the original set
/// if reduction cannot proceed.
pub fn ddmin<F>(indices: &[usize], fails: F) -> Vec<usize>
where
    F: Fn(&[usize]) -> bool,
{
    if indices.is_empty() {
        return vec![];
    }
    if !fails(indices) {
        // Not a failing set — nothing to reduce.
        return indices.to_vec();
    }
    ddmin_rec(indices, 2, &fails)
}

fn ddmin_rec<F>(indices: &[usize], n: usize, fails: &F) -> Vec<usize>
where
    F: Fn(&[usize]) -> bool,
{
    let len = indices.len();
    if len == 1 {
        return indices.to_vec();
    }
    let n = n.min(len);
    let chunk = (len + n - 1) / n;

    // Try subsets
    for i in 0..n {
        let start = i * chunk;
        if start >= len {
            break;
        }
        let end = (start + chunk).min(len);
        let subset = &indices[start..end];
        if fails(subset) {
            return ddmin_rec(subset, 2, fails);
        }
    }

    // Try complements
    for i in 0..n {
        let start = i * chunk;
        if start >= len {
            break;
        }
        let end = (start + chunk).min(len);
        let mut complement = Vec::with_capacity(len - (end - start));
        complement.extend_from_slice(&indices[..start]);
        complement.extend_from_slice(&indices[end..]);
        if !complement.is_empty() && fails(&complement) {
            return ddmin_rec(&complement, n.saturating_sub(1).max(2), fails);
        }
    }

    if n < len {
        return ddmin_rec(indices, (n * 2).min(len), fails);
    }
    indices.to_vec()
}

/// Reduce axis labels to the smallest failing combination.
pub fn reduce_axes(axes: &[String], fails: impl Fn(&[String]) -> bool) -> Vec<String> {
    let indices: Vec<usize> = (0..axes.len()).collect();
    let kept = ddmin(&indices, |subset| {
        let labels: Vec<String> = subset.iter().map(|&i| axes[i].clone()).collect();
        fails(&labels)
    });
    kept.into_iter().map(|i| axes[i].clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_single_culprit() {
        // Failure only when index 2 is present
        let indices = vec![0, 1, 2, 3, 4];
        let result = ddmin(&indices, |s| s.contains(&2));
        assert_eq!(result, vec![2]);
    }

    #[test]
    fn finds_pair_culprit() {
        let indices = vec![0, 1, 2, 3];
        let result = ddmin(&indices, |s| s.contains(&1) && s.contains(&3));
        assert!(result.contains(&1) && result.contains(&3));
        assert!(result.len() <= 2);
    }

    #[test]
    fn empty_input() {
        assert!(ddmin(&[], |_| true).is_empty());
    }

    #[test]
    fn reduce_axes_labels() {
        let axes = vec!["runtime".into(), "deps".into(), "image".into()];
        let reduced = reduce_axes(&axes, |s| s.iter().any(|x| x == "deps"));
        assert_eq!(reduced, vec!["deps".to_string()]);
    }
}
