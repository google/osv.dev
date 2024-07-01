"""impact_git_test.py: Tests for the impact module using git repositories."""

from .test_tools.test_repository import TestRepository

import unittest
from . import impact


class GitImpactTest(unittest.TestCase):
  """Tests for the impact module using git repositories."""

  @classmethod
  def setUpClass(cls):
    cls.__repo_analyzer = impact.RepoAnalyzer(detect_cherrypicks=False)

  ######## 1st : tests with "introduced" and "fixed"
  def test_introduced_fixed_linear(self):
    """Simple range, only two commits are vulnerable. 
    Model : A->B->C->D """
    events = {"B": "introduced", "D": "fixed"}
    expected_vulnerable = {"B", "C"}
    self.template_four_linear(events, expected_vulnerable,
                              "test_introduced_fixed_linear")

  ######## 2nd : tests with "introduced" and "limit"
  def test_introduced_limit_linear(self):
    """Ensures the basic behavior of limit 
    (the limit commit is considered unaffected).
    Model : A->B->C->D """
    events = {"B": "introduced", "D": "limit"}
    expected_vulnerable = {"B", "C"}
    self.template_four_linear(events, expected_vulnerable,
                              "test_introduced_limit_linear")

  ######## 3nd : tests with "introduced" and "last-affected"
  def test_introduced_last_affected_linear(self):
    """Ensures the basic behavior of last_affected 
    commits (the last_affected commit is considered affected).
    Model : A->B->C->D """
    events = {"B": "introduced", "D": "last_affected"}
    expected_vulnerable = {"B", "C", "D"}
    self.template_four_linear(events, expected_vulnerable,
                              "test_introduced_last_affected_linear")

  ######## 4nd : tests with "introduced", "limit", and "fixed"
  def test_introduced_limit_fixed_linear_lf(self):
    """Ensures the behaviors of limit and fixed commits are not conflicting.
    Model : A->B->C->D """
    events = {"B": "introduced", "C": "limit", "D": "fixed"}
    expected_vulnerable = {"B"}
    self.template_four_linear(events, expected_vulnerable,
                              "test_introduced_limit_fixed_linear_lf")

  ######## 5nd : tests with "introduced", "limit",
  # and "fixed" in a different order
  def test_introduced_limit_fixed_linear_fl(self):
    """Ensures the behaviors of limit and fixed commits are not conflicting.
    Model : A->B->C->D """
    events = {"B": "introduced", "C": "fixed", "D": "limit"}
    expected_vulnerable = {"B"}
    self.template_four_linear(events, expected_vulnerable,
                              "test_introduced_limit_fixed_linear_fl")

######## 6nd : branch tests with "introduced", and "fixed"

  def test_introduced_fixed_branch_propagation(self):
    """Simple range, checking the propagation of the 
    vulnerability in created branch. 
    Model :   A->B->C->D 
                    |->E"""
    events = {
        "B": "introduced",
        "D": "fixed",
    }
    expected_vulnerable = {"B", "C", "E"}
    self.template_five_last_branch(events, expected_vulnerable,
                                   "test_introduced_fixed_branch_propagation")

######## 7nd : branch tests with "introduced" and "limit"

  def test_introduced_limit_branch(self):
    """ensures the basic behavior of limit commits in branches. 
    Model :   A->B->C->D 
                    |->E"""
    events = {
        "B": "introduced",
        "D": "limit",
    }
    expected_vulnerable = {"B", "C"}
    self.template_five_last_branch(events, expected_vulnerable,
                                   "test_introduced_limit_branch")

######## 8nd : branch tests with "introduced" and "last-affected"

  def test_introduced_last_affected_branch_propagation(self):
    """ensures the basic behavior of last_affected commits when 
    the repository has a branch. 
    Model :   A->B->C->D 
                    |->E"""
    events = {
        "B": "introduced",
        "D": "last_affected",
    }
    expected_vulnerable = {"B", "C", "D", "E"}
    self.template_five_last_branch(
        events, expected_vulnerable,
        "test_introduced_last_affected_branch_propagation")

######## 9nd : merge tests with "introduced" and "fixed"

  def test_introduced_fixed_merge(self):
    """ Simple range, checking the non propagation of the 
    vulnerability in the created branch . 
    Model :      A ->B-> D->E 
                  |->C-/^"""
    events = {"B": "introduced", "E": "fixed"}
    expected_vulnerable = {"B", "D"}
    self.template_five_second_branch_merge(events, expected_vulnerable,
                                           "test_introduced_fixed_merge")

######## 10nd : merge tests with "introduced" and "limit"

  def test_introduced_limit_merge(self):
    """ Simple range, checking the non propagation of the 
    vulnerability in created branch with a limit commit. 
    Model :      A ->B-> D->E 
                  |->C-/^"""
    events = {"B": "introduced", "E": "limit"}
    expected_vulnerable = {"B", "D"}
    self.template_five_second_branch_merge(events, expected_vulnerable,
                                           "test_introduced_limit_merge")

######## 11nd : merge tests with "introduced" and "last-affected"

  def test_introduced_last_affected_merge(self):
    """ Simple range, checking the non propagation of the vulnerability 
    in the created branch with a last-affected commit. 
    Model :      A ->B-> D->E 
                  |->C-/^"""
    events = {"B": "introduced", "E": "last_affected"}
    expected_vulnerable = {"B", "D", "E"}
    self.template_five_second_branch_merge(
        events, expected_vulnerable, "test_introduced_last_affected_merge")

######## 12nd : merge tests with "introduced", and two "fixed",
# one in the created branch and one in the main branch

  def test_introduced_fixed_merge_fix_propagation(self):
    """ Srange with two fixed, checking the propagation of the fix 
    from the created branch to the main branch. 
    Model :      A ->B-> D->E 
                  |->C-/^"""
    events = {"B": "introduced", "C": "fixed"}
    expected_vulnerable = {"B"}
    self.template_five_second_branch_merge(
        events, expected_vulnerable,
        "test_introduced_fixed_merge_fix_propagation")

######## 13nd : linear tests with two "introduced" and two "fixed" intercalated

  def test_introduced_fixed_two_linear(self):
    """ Srange with two fixed, checking the non propagation of the 
    fix from the created branch to the main branch. 
    Model :      A->B->C->D->E """
    events = {"B": "introduced", "C": "fixed", "D": "introduced", "E": "fixed"}
    expected_vulnerable = {"B", "D"}
    self.template_five_linear(events, expected_vulnerable,
                              "test_introduced_fixed_two_linear")

######## 14nd : linear tests with two "introduced" and two "limit" intercalated

  def test_introduced_limit_two_linear(self):
    """ Srange with two fixed, checking the non propagation of the 
    fix from the created branch to the main branch. 
    Model :      A->B->C->D->E """
    events = {"B": "introduced", "C": "limit", "D": "introduced", "E": "limit"}
    expected_vulnerable = {"B", "D"}
    self.template_five_linear(events, expected_vulnerable,
                              "test_introduced_limit_two_linear")

######## 15nd : linear tests with two "introduced" and
# two "last_affected" intercalated

  def test_introduced_last_affected_two_linear(self):
    """ Srange with two fixed, checking the non propagation of the 
    fix from the created branch to the main branch. 
    Model :      A->B->C->D->E """
    events = {
        "B": "introduced",
        "C": "last_affected",
        "D": "introduced",
        "E": "last_affected"
    }
    expected_vulnerable = {"C", "E", "B", "D"}
    self.template_five_linear(events, expected_vulnerable,
                              "test_introduced_last_affected_two_linear")


######## 16nd : testing the behavior of limit with a branch

  def test_introduced_limit_branch_limit(self):
    """ range with. 
    Model :      A ->B-> C->E 
                     |-> D"""
    events = {"B": "introduced", "D": "limit", "E": "fixed"}
    expected_vulnerable = {"B"}
    self.template_five_third_branch(events, expected_vulnerable,
                                    "test_introduced_limit_branch_limit")

  ###### Utility Template methods
  def template_four_linear(self, events: dict, expected, name):
    """Linear template with 4 commits  
    A->B->C->D """
    repo = TestRepository(name, debug=False)
    repo.add_commit(
        message="B",
        parents=[repo.get_head_hex()],
        event_type=events.get("B", None))
    repo.add_commit(
        message="C",
        parents=[repo.get_head_hex()],
        event_type=events.get("C", None))
    repo.add_commit(
        message="D",
        parents=[repo.get_head_hex()],
        event_type=events.get("D", None))
    repo.create_remote_branch()

    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()
    expected_commits = repo.get_commits_ids(expected)

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)
    result_commit_message = repo.get_message_by_commits_id(result.commits)
    repo.clean()
    self.assertEqual(
        result.commits,
        expected_commits,
        "Expected: %s, got: %s" % (expected, result_commit_message),
    )

  def template_five_linear(self, events, expected, name):
    """Linear template with 5 commits  
    A->B->C->D """
    repo = TestRepository(name, debug=False)
    repo.add_commit(
        message="B",
        parents=[repo.get_head_hex()],
        event_type=events.get("B", None))
    repo.add_commit(
        message="C",
        parents=[repo.get_head_hex()],
        event_type=events.get("C", None))
    repo.add_commit(
        message="D",
        parents=[repo.get_head_hex()],
        event_type=events.get("D", None))
    repo.add_commit(
        message="E",
        parents=[repo.get_head_hex()],
        event_type=events.get("E", None))

    repo.create_remote_branch()

    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()

    expected_commits = repo.get_commits_ids(expected)

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)
    result_commit_message = repo.get_message_by_commits_id(result.commits)
    repo.clean()
    self.assertEqual(
        result.commits,
        expected_commits,
        "Expected: %s, got: %s" % (expected, result_commit_message),
    )

  def template_five_last_branch(self, events, expected, name):
    """Template with 5 commits, the last one in a different branch
       
    A->B->C->D 
          |->E """
    repo = TestRepository(name, debug=False)
    repo.add_commit(
        message="B",
        parents=[repo.get_head_hex()],
        event_type=events.get("B", None))
    c = repo.add_commit(
        message="C",
        parents=[repo.get_head_hex()],
        event_type=events.get("C", None))
    repo.create_branch_if_needed_and_checkout("feature")
    repo.add_commit(message="E", parents=[c], event_type=events.get("E", None))
    repo.checkout("main")
    repo.add_commit(
        message="D",
        parents=[repo.get_head_hex()],
        event_type=events.get("D", None))
    repo.create_remote_branch()

    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()
    expected_commits = repo.get_commits_ids(expected)

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)
    result_commit_message = repo.get_message_by_commits_id(result.commits)
    repo.clean()
    self.assertEqual(
        result.commits,
        expected_commits,
        "Expected: %s, got: %s" % (expected, result_commit_message),
    )

  def template_five_second_branch_merge(self, events, expected, name):
    """Template with 5 commits, the second one in a different 
    branch and merged right after 
      
    A->B->D->E 
    |->C-/^ """
    repo = TestRepository(name, debug=False)
    repo.create_branch_if_needed_and_checkout("feature")
    c = repo.add_commit(
        message="C",
        parents=[repo.get_head_hex()],
        event_type=events.get("C", None))
    repo.checkout("main")
    repo.add_commit(
        message="B",
        parents=[repo.get_head_hex()],
        event_type=events.get("B", None))
    repo.merge(message="D", commit=c, event_type=events.get("D", None))
    repo.add_commit(
        message="E",
        parents=[repo.get_head_hex()],
        event_type=events.get("E", None))
    repo.create_remote_branch()

    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()
    expected_commits = repo.get_commits_ids(expected)

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)
    result_commit_message = repo.get_message_by_commits_id(result.commits)
    repo.clean()
    self.assertEqual(
        result.commits,
        expected_commits,
        "Expected: %s, got: %s" % (expected, result_commit_message),
    )

  def template_six_second_branch_merge(self, events, expected, name):
    """Template with 6 commits, the second one in a different branch and 
    merged after two commits in the main branch

    A->B->C->E->F  
    |->  D -/^ """
    repo = TestRepository(name, debug=False)
    repo.create_branch_if_needed_and_checkout("feature")
    d = repo.add_commit(
        message="D",
        parents=[repo.get_head_hex()],
        event_type=events.get("D", None))
    repo.checkout("main")
    repo.add_commit(
        message="B",
        parents=[repo.get_head_hex()],
        event_type=events.get("B", None))
    repo.add_commit(
        message="C",
        parents=[repo.get_head_hex()],
        event_type=events.get("C", None))
    repo.merge(message="E", commit=d, event_type=events.get("E", None))
    repo.add_commit(
        message="F",
        parents=[repo.get_head_hex()],
        event_type=events.get("F", None))

    repo.create_remote_branch()

    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()
    expected_commits = repo.get_commits_ids(expected)

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)
    result_commit_message = repo.get_message_by_commits_id(result.commits)
    repo.clean()
    self.assertEqual(
        result.commits,
        expected_commits,
        "Expected: %s, got: %s" % (expected, result_commit_message),
    )

  def template_five_third_branch(self, events, expected, name):
    """Template with 5 commits, the third one in a different branch, not merged
      
    A->B->C->E   
       |->D"""
    repo = TestRepository(name, debug=False)
    repo.add_commit(
        message="B",
        parents=[repo.get_head_hex()],
        event_type=events.get("B", None))
    repo.create_branch_if_needed_and_checkout("feature")
    repo.add_commit(
        message="D",
        parents=[repo.get_head_hex()],
        event_type=events.get("D", None))
    repo.checkout("main")
    repo.add_commit(
        message="C",
        parents=[repo.get_head_hex()],
        event_type=events.get("C", None))
    repo.add_commit(
        message="E",
        parents=[repo.get_head_hex()],
        event_type=events.get("E", None))

    repo.create_remote_branch()
    (all_introduced, all_fixed, all_last_affected,
     all_limit) = repo.get_ranges()
    expected_commits = repo.get_commits_ids(expected)

    result = self.__repo_analyzer.get_affected(repo.repo, all_introduced,
                                               all_fixed, all_limit,
                                               all_last_affected)
    result_commit_message = repo.get_message_by_commits_id(result.commits)
    repo.clean()
    self.assertEqual(
        result.commits,
        expected_commits,
        "Expected: %s, got: %s" % (expected, result_commit_message),
    )
