"""impact_git_test.py: Tests for the impact module using git repositories."""

from .test_tools.test_repository import TestRepository
import unittest
from . import impact


class GitImpactTest(unittest.TestCase):
  """Tests for the impact module using git repositories."""

  @classmethod
  def setUpClass(cls):
    cls.__repo_analyzer = impact.RepoAnalyzer(detect_cherrypicks=False)

  ######## 1rst : tests with only "introduced" and "fixed"

  def test_introduced_fixed_linear(self):
    """Simple range, only two commits are vulnerable. """

    repo = TestRepository("test_introduced_fixed_linear", debug=False)

    first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    second = repo.add_empty_commit(parents=[first])
    repo.add_empty_commit(
        parents=[second], vulnerability=TestRepository.VulnerabilityType.FIXED)
    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)

    expected = set([first.hex, second.hex])
    repo.remove()
    self.assertEqual(
        result.commits,
        expected,
        "Expected: %s, got: %s" % (expected, result.commits),
    )

  def test_introduced_fixed_branch_propagation(self):
    """Ensures the detection of the propagation 
    of the vulnerability in created branches"""
    repo = TestRepository(
        "test_introduced_fixed_branch_propagation", debug=False)

    first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    second = repo.add_empty_commit(parents=[first])
    repo.add_empty_commit(
        parents=[second], vulnerability=TestRepository.VulnerabilityType.FIXED)
    fourth = repo.add_empty_commit(parents=[second])
    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)

    expected = set([first.hex, second.hex, fourth.hex])
    repo.remove()
    self.assertEqual(
        result.commits,
        expected,
        "Expected: %s, got: %s" % (expected, result.commits),
    )

  def test_introduced_fixed_merge(self):
    """Ensures that a merge without a fix does not 
    affect the propagation of a vulnerability"""
    repo = TestRepository("test_introduced_fixed_merge", debug=False)

    first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    second = repo.add_empty_commit()
    third = repo.add_empty_commit(parents=[first, second])
    repo.add_empty_commit(
        parents=[third], vulnerability=TestRepository.VulnerabilityType.FIXED)
    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)

    expected = set([first.hex, third.hex])
    repo.remove()
    self.assertEqual(
        result.commits,
        expected,
        "Expected: %s, got: %s" % (expected, result.commits),
    )

  def test_introduced_fixed_two_linear(self):
    """Ensures that multiple introduced commit 
    in the same branch are correctly handled"""
    repo = TestRepository("test_introduced_fixed_two_linear", debug=False)

    first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    second = repo.add_empty_commit(
        parents=[first], vulnerability=TestRepository.VulnerabilityType.FIXED)
    third = repo.add_empty_commit(
        parents=[second],
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    repo.add_empty_commit(
        parents=[third], vulnerability=TestRepository.VulnerabilityType.FIXED)
    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)

    expected = set([first.hex, third.hex])
    repo.remove()
    self.assertEqual(
        result.commits,
        expected,
        "Expected: %s, got: %s" % (expected, result.commits),
    )

  def test_introduced_fixed_merge_propagation(self):
    """Ensures that a vulnerability is propagated from 
    a branch, in spite of the main branch having a fix."""

    repo = TestRepository(
        "test_introduced_fixed_merge_propagation", debug=False)

    first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    second = repo.add_empty_commit(
        parents=[first], vulnerability=TestRepository.VulnerabilityType.FIXED)
    third = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    fourth = repo.add_empty_commit(parents=[second, third])
    repo.add_empty_commit(
        parents=[fourth], vulnerability=TestRepository.VulnerabilityType.FIXED)
    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)

    expected = set([first.hex, third.hex, fourth.hex])
    repo.remove()
    self.assertEqual(
        result.commits,
        expected,
        "Expected: %s, got: %s" % (expected, result.commits),
    )

  def test_introduced_fixed_fix_propagation(self):
    """Ensures that a fix gets propagated, in the case of a merge"""
    repo = TestRepository("test_introduced_fixed_fix_propagation")

    first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    second = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.FIXED)
    third = repo.add_empty_commit(parents=[first, second])
    repo.add_empty_commit(
        parents=[third], vulnerability=TestRepository.VulnerabilityType.FIXED)
    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)

    expected = set([first.hex])
    repo.remove()
    self.assertEqual(
        result.commits,
        expected,
        "Expected: %s, got: %s" % (expected, result.commits),
    )

  ######## 2nd : tests with "introduced" and "limit"

  def test_introduced_limit_linear(self):
    """Ensures the basic behavior of limit 
    (the limit commit is considered unaffected)."""
    repo = TestRepository("test_intoduced_limit_linear")

    first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    second = repo.add_empty_commit(parents=[first])
    repo.add_empty_commit(
        parents=[second], vulnerability=TestRepository.VulnerabilityType.LIMIT)
    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)

    expected = set([first.hex, second.hex])
    repo.remove()
    self.assertEqual(
        result.commits,
        expected,
        "Expected: %s, got: %s" % (expected, result.commits),
    )

  def test_introduced_limit_branch(self):
    """Ensures that a limit commit does limit the vulnerability to a branch."""
    repo = TestRepository("test_intoduced_limit_branch")

    first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    second = repo.add_empty_commit(parents=[first])
    repo.add_empty_commit(
        parents=[second], vulnerability=TestRepository.VulnerabilityType.LIMIT)
    repo.add_empty_commit(parents=[second])
    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()
    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)

    expected = set([
        first.hex,
        second.hex,
    ])
    repo.remove()
    self.assertEqual(
        result.commits,
        expected,
        "Expected: %s, got: %s" % (expected, result.commits),
    )

  def test_introduced_limit_merge(self):
    """Ensures that a merge without a fix does 
    not affect the propagation of a vulnerability."""
    repo = TestRepository("test_intoduced_limit_merge", debug=False)

    first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    second = repo.add_empty_commit()
    third = repo.add_empty_commit(parents=[first, second])
    repo.add_empty_commit(
        parents=[third], vulnerability=TestRepository.VulnerabilityType.LIMIT)
    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)

    expected = set([first.hex, third.hex])
    repo.remove()
    self.assertEqual(
        result.commits,
        expected,
        "Expected: %s, got: %s" % (expected, result.commits),
    )

  def test_introduced_limit_two_linear(self):
    """Ensures that multiple introduced commit in
    the same branch are correctly handled, wrt limit."""
    repo = TestRepository("test_introduced_limit_two_linear", debug=False)

    first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    second = repo.add_empty_commit(
        parents=[first], vulnerability=TestRepository.VulnerabilityType.LIMIT)
    third = repo.add_empty_commit(
        parents=[second],
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    repo.add_empty_commit(
        parents=[third], vulnerability=TestRepository.VulnerabilityType.LIMIT)
    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)

    expected = set([first.hex, third.hex])
    repo.remove()
    self.assertEqual(
        result.commits,
        expected,
        "Expected: %s, got: %s" % (expected, result.commits),
    )

  ######## 2nd : tests with "introduced" and "last-affected"

  def test_introduced_last_affected_linear(self):
    """Ensures the basic behavior of last_affected 
    commits (the las_affected commit is considered affected)."""
    repo = TestRepository("test_introduced_last_affected_linear")

    first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    second = repo.add_empty_commit(parents=[first])
    third = repo.add_empty_commit(
        parents=[second],
        vulnerability=TestRepository.VulnerabilityType.LAST_AFFECTED,
    )
    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)

    expected = set([first.hex, second.hex, third.hex])
    repo.remove()
    self.assertEqual(
        result.commits,
        expected,
        "Expected: %s, got: %s" % (expected, result.commits),
    )

  def test_introduced_last_affected_branch_propagation(self):
    """Ensures that vulnerabilities are propagated to branches"""
    repo = TestRepository(
        "test_introduced_last_affected_branch_propagation", debug=False)

    first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    second = repo.add_empty_commit(parents=[first])
    third = repo.add_empty_commit(
        parents=[second],
        vulnerability=TestRepository.VulnerabilityType.LAST_AFFECTED,
    )
    fourth = repo.add_empty_commit(parents=[second])
    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)

    expected = set([first.hex, second.hex, third.hex, fourth.hex])
    repo.remove()
    self.assertEqual(
        result.commits,
        expected,
        "Expected: %s, got: %s" % (expected, result.commits),
    )

  def test_introduced_last_affected_merge(self):
    """Ensures that a merge without a fix does 
    not affect the propagation of a vulnerability."""
    repo = TestRepository("test_introduced_last_affected_merge", debug=False)

    first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    second = repo.add_empty_commit()
    third = repo.add_empty_commit(parents=[first, second])
    fourth = repo.add_empty_commit(
        parents=[third],
        vulnerability=TestRepository.VulnerabilityType.LAST_AFFECTED,
    )
    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)

    expected = set([first.hex, third.hex, fourth.hex])
    repo.remove()
    self.assertEqual(
        result.commits,
        expected,
        "Expected: %s, got: %s" % (expected, result.commits),
    )

  def test_introduced_last_affected_two_linear(self):
    """Ensures that multiple introduced commit in 
    the same branch are correctly handled, wrt last_affected."""
    repo = TestRepository(
        "test_introduced_last_affected_two_linear", debug=False)

    first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    second = repo.add_empty_commit(
        parents=[first],
        vulnerability=TestRepository.VulnerabilityType.LAST_AFFECTED,
    )
    third = repo.add_empty_commit(
        parents=[second],
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    fourth = repo.add_empty_commit(
        parents=[third],
        vulnerability=TestRepository.VulnerabilityType.LAST_AFFECTED,
    )

    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)

    expected = set([first.hex, second.hex, third.hex, fourth.hex])
    repo.remove()
    self.assertEqual(
        result.commits,
        expected,
        "Expected: %s, got: %s" % (expected, result.commits),
    )

  ######## 3nd : tests with "introduced", "limit", and "fixed"

  def test_introduced_limit_fixed_linear_lf(self):
    """Ensures the behaviors of limit and fixed commits are not conflicting."""
    repo = TestRepository("test_introduced_limit_fixed_linear_lf")

    first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    second = repo.add_empty_commit(
        parents=[first], vulnerability=TestRepository.VulnerabilityType.LIMIT)
    repo.add_empty_commit(
        parents=[second], vulnerability=TestRepository.VulnerabilityType.FIXED)

    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)

    expected = set([first.hex])
    repo.remove()
    self.assertEqual(
        result.commits,
        expected,
        "Expected: %s, got: %s" % (expected, result.commits),
    )

  def test_introduced_limit_fixed_linear_fl(self):
    """Ensures the behaviors of limit and fixed commits are not conflicting"""
    repo = TestRepository("test_introduced_limit_fixed_linear_lf")

    first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    second = repo.add_empty_commit(
        parents=[first], vulnerability=TestRepository.VulnerabilityType.FIXED)
    repo.add_empty_commit(
        parents=[second], vulnerability=TestRepository.VulnerabilityType.LIMIT)

    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()
    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)

    expected = set([first.hex])
    repo.remove()
    self.assertEqual(
        result.commits,
        expected,
        "Expected: %s, got: %s" % (expected, result.commits),
    )

  def test_introduced_limit_branch_limit(self):
    """Ensures the behaviors of limit and fixed
    commits are not conflicting, in the case of a branch created."""
    repo = TestRepository("test_introduced_limit_fixed_linear_lf", debug=False)

    first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
    second = repo.add_empty_commit(
        parents=[first], vulnerability=TestRepository.VulnerabilityType.LIMIT)
    repo.add_empty_commit(parents=[first])
    repo.add_empty_commit(
        parents=[second], vulnerability=TestRepository.VulnerabilityType.FIXED)

    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()
    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)

    expected = set([first.hex])
    repo.remove()
    self.assertEqual(
        result.commits,
        expected,
        "Expected: %s, got: %s" % (expected, result.commits),
    )