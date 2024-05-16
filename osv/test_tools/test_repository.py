""" Utility class to create a test repository for the git tests

This module contains a class that creates a test repository for the git tests
It can be used to create a test repository and add commits tagged with different
vulnerability types.

usage:
  repo = TestRepository("test_introduced_fixed_linear", debug=False)

  first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
  second = repo.add_empty_commit(parents=[first])
  repo.add_empty_commit(
        parents=[second], vulnerability=TestRepository.VulnerabilityType.FIXED)
"""
import pygit2
import json
from datetime import datetime
import os
import shutil
import uuid
import logging
from osv import vulnerability_pb2


class CommitsInfo:
  """Internal class to store the commits information
  """

  class Messages:
    """Single commit information
    """

    def __init__(self):
      self._commit_to_message: dict[str, str] = {}
      self._message_to_commit: dict[str, str] = {}

    def add_commit(self, commit_id, commit_message):
      self._commit_to_message[commit_id] = commit_message
      self._message_to_commit[commit_message] = commit_id

    def get_message(self, commit_id):
      return self._commit_to_message.get(commit_id)

    def get_commit_id(self, commit_message):
      return self._message_to_commit.get(commit_message)

    def get_commits_ids(self, commit_messages):
      commit_ids = set()
      for commit_message in commit_messages:
        commit_id = self.get_commit_id(commit_message)
        if commit_id is not None:
          commit_ids.add(commit_id)
      return commit_ids

    def get_messages(self, commits_id):
      commit_messages = set()
      for commit_id in commits_id:
        commit_message = self.get_message(commit_id)
        if commit_message is not None:
          commit_messages.add(commit_message)
      return commit_messages

    def existing_message(self, message):
      return message in self._message_to_commit

  def __init__(self):
    self.messages: CommitsInfo.Messages = CommitsInfo.Messages()
    self._events: list[vulnerability_pb2.Event] = []

  def add_commit(self, commit_id, commit_message, event_type: str = None):
    """Adds a commit to the repository

    Args:
        commit_id (str): The id of the commit
        commit_message (str): The message of the commit
        event_type (str, optional): the type of the event. Defaults to None.

    Raises:
        ValueError: In the case of an invalid vulnerability type
    """
    if not self.messages.existing_message(commit_message):
      if event_type:
        keys = vulnerability_pb2.Event.DESCRIPTOR.fields_by_name.keys()
        if event_type not in keys:
          raise ValueError("Invalid vulnerability type")
        self._events.append(vulnerability_pb2.Event(**{event_type: commit_id}))
      self.messages.add_commit(commit_id, commit_message)
    else:
      raise ValueError("Commit message already exists")

  def get_ranges(self):
    """get the ranges of the repository, 
    each range containing the corresponding ids

    Raises:
        ValueError: In the case of an invalid vulnerability type

    Returns:
        tuple : a tuple containing the introduced, fixed, 
          last_affected and limit commits
    """
    introduced = []
    fixed = []
    last_affected = []
    limit = []
    for event in self._events:
      if event.introduced and event.introduced != '0':
        introduced.append(event.introduced)
        continue

      if event.last_affected:
        last_affected.append(event.last_affected)
        continue

      if event.fixed:
        fixed.append(event.fixed)
        continue

      if event.limit:
        limit.append(event.limit)
        continue
    return (introduced, fixed, last_affected, limit)


class TestRepository:
  """ Utility class to create a test repository for the git tests
  """
  _author = pygit2.Signature('John Smith', 'johnSmith@example.com')
  _commiter = pygit2.Signature('John Smith', 'johnSmith@example.com')

  def __init__(self, name: str, debug: bool = False):
    self.repo_path = f"osv/testdata/test_repositories/{name}"
    self.debug = debug
    self.name = name
    self.commits_info = CommitsInfo()

    #delete the repository if it already exists
    if os.path.exists(self.repo_path):
      self.clean()
    #initialize the repository
    self.repo: pygit2._pygit2.Repository = pygit2.init_repository(
        self.repo_path, bare=False)
    #create an initial commit
    parent = []
    self.add_commit(message="A", parents=parent)

  def merge(self, message, commit, event_type: str = None):
    """merge a commit into the repository

    Args:
        commit (str): the hex of the commit to be merged
        event_type (str, optional): the event associated with the commit.
        Defaults to None.
    """
    self.repo.merge(commit)
    self.add_commit(message, [self.get_head_hex(), commit], event_type)

  def get_commits_ids(self, commit_messages):
    return self.commits_info.messages.get_commits_ids(commit_messages)

  def add_commit(self, message, parents=None, event_type: str = None):
    """Add a commit to the repository

    Args:
        message (str): the message of the commit
        parents (List(str), optional): the list of parents
          of the current repository . Defaults to None.
        event (str, optional): the type of event corresponding
          to the commit. Defaults to None.

    Returns:
        str: the hex id of the commit
    """
    if parents is None:
      parents = [self.get_head_hex()]
    random_str = str(uuid.uuid1())
    with open(f"{self.repo_path}/{ random_str}", "w") as f:
      f.write(random_str)
    index = self.repo.index
    index.add_all()
    tree = index.write_tree()
    index.write()
    commit_hex = self.repo.create_commit('HEAD', self._author, self._commiter,
                                         message, tree, parents).hex
    self.commits_info.add_commit(commit_hex, message, event_type)
    return commit_hex

  def get_head_hex(self):
    return self.get_head().hex

  def get_head(self):
    return self.repo.revparse_single('HEAD')

  def checkout(self, branchname):
    branch = self.repo.lookup_branch(branchname)
    ref = self.repo.lookup_reference(branch.name)
    self.repo.checkout(ref)

  def create_branch_if_needed_and_checkout(self, branchname):
    if not self.repo.branches.get(branchname):
      self.repo.create_branch(branchname, self.get_head())
    self.checkout(branchname)

  def create_remote_branch(self):
    for branch_name in self.repo.branches:
      branch = self.repo.branches.get(branch_name)
      self.repo.references.create(f'refs/remotes/origin/{branch_name}',
                                  branch.raw_target)

  def clean(self):
    shutil.rmtree(self.repo_path)
    ##cleanup
    self.introduced = []
    self.fixed = []
    self.last_affected = []
    self.limit = []

  def get_ranges(self):
    """
        return the ranges of the repository
        """
    return self.commits_info.get_ranges()

  def get_message_by_commits_id(self, commits_id):
    return self.commits_info.messages.get_messages(commits_id)

  def print_commits(self):
    """ prints the commits of the repository
    """
    logging.debug(self.name)
    commits = []
    for ref in self.repo.listall_reference_objects():
      logging.debug(ref.target)
      for commit in self.repo.walk(ref.target, pygit2.GIT_SORT_TIME):

        current_commit = {
            'hash':
                commit.hex,
            'message':
                commit.message,
            'commit_date':
                datetime.utcfromtimestamp(commit.commit_time
                                         ).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'author_name':
                commit.author.name,
            'author_email':
                commit.author.email,
            'parents': [c.hex for c in commit.parents],
        }
        if current_commit in commits:
          break
        commits.append(current_commit)

    logging.debug(json.dumps(commits, indent=2))
