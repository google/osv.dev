"""test_repository"""
import pygit2
import json
from datetime import datetime
from enum import Enum
import os
import shutil
import uuid


class TestRepository:
  """ Utilitary class to create a test repository for the git tests
  """

  class VulnerabilityType(Enum):
    INTRODUCED = 1
    FIXED = 2
    LAST_AFFECTED = 3
    LIMIT = 4
    NONE = 5

  _author = pygit2.Signature('John Smith', 'johnSmith@example.com')
  _commiter = pygit2.Signature('John Smith', 'johnSmith@example.com')

  _initial_commit = None

  def __init__(self, name: str, debug: bool = False):
    self.debug = debug
    self.name = name
    self.introduced = []
    self.fixed = []
    self.last_affected = []
    self.limit = []

    if os.path.exists(f"osv/testdata/test_repositories/{name}"):
      shutil.rmtree(f"osv/testdata/test_repositories/{name}")
    self.repo = pygit2.init_repository(
        f"osv/testdata/test_repositories/{name}", bare=False)
    #empty initial commit usefull for the creation of the repository
    tree = self.repo.TreeBuilder().write()
    self._initial_commit = self.repo.create_commit('refs/heads/main',
                                                   self._author, self._commiter,
                                                   "message", tree, [])
    self.create_branch(f"branch_{self._initial_commit.hex}",
                       self._initial_commit)
    self.repo.references.create("refs/remotes/origin/main",
                                self._initial_commit)

  def create_branch(self, name: str, commit: pygit2.Oid):
    self.repo.references.create(f'refs/heads/{name}', commit)
    self.repo.references.create(f'refs/remotes/origin/{name}', commit)

  def add_empty_commit(
      self,
      parents: list[pygit2.Oid] = None,
      vulnerability: VulnerabilityType = VulnerabilityType.NONE,
      message: str = "Empty") -> pygit2.Oid:
    """
    Adds a empty commit to the repository, tags it with the vulnerability 
    type and adds it to the vulnerability list if specified 
    """

    tree = self.repo.TreeBuilder().write()
    self._author = pygit2.Signature(
        str(uuid.uuid1()), 'johnSmith@example.com'
    )  #using a random uuid to avoid commits being the same
    commit = None

    if not parents or len(parents) == 0:
      self.repo.create_branch(
          'branch_temp', self.repo.revparse_single(self._initial_commit.hex))
      commit = self.repo.create_commit('refs/heads/branch_temp', self._author,
                                       self._commiter, message, tree,
                                       [self._initial_commit])

      self.repo.branches.delete('branch_temp')
      self.create_branch(f'branch_{commit.hex}', commit)

    else:
      self.repo.create_branch('branch_temp',
                              self.repo.revparse_single(parents[0].hex))
      commit = self.repo.create_commit('refs/heads/branch_temp', self._author,
                                       self._commiter, message, tree, parents)
      self.repo.branches.delete('branch_temp')
      self.create_branch(commit=commit, name=f'branch_{commit.hex}')

    self.repo.references.get('refs/remotes/{0}/{1}'.format(
        "origin", "main")).set_target(commit)
    self.repo.references.get('refs/heads/main').set_target(commit)

    if self.debug:
      os.system("echo -------------------------------" +
                "-----------------------------------")
      os.system(f"git -C osv/testdata/test_repositories/{self.name}" +
                " log --all --graph --decorate")

      #self.repo.branches.delete(created_branch.branch_name)

    match vulnerability:
      case self.VulnerabilityType.INTRODUCED:
        self.introduced.append(commit.hex)
      case self.VulnerabilityType.FIXED:
        self.fixed.append(commit.hex)
      case self.VulnerabilityType.LAST_AFFECTED:
        self.last_affected.append(commit.hex)
      case self.VulnerabilityType.LIMIT:
        self.limit.append(commit.hex)
      case self.VulnerabilityType.NONE:
        pass
      case _:
        raise ValueError("Invalid vulnerability type")
    return commit

  def remove(self):
    shutil.rmtree(f"osv/testdata/test_repositories/{self.name}/")
    while os.path.exists(
        f"osv/testdata/test_repositories/{self.name}/"):  # check if it exists
      pass
    ##cleanup
    self.introduced = []
    self.fixed = []
    self.last_affected = []
    self.limit = []

  def get_ranges(self):
    """
        return the ranges of the repository
        """
    return (self.introduced, self.fixed, self.last_affected, self.limit)

  def print_commits(self):
    """ prints the commits of the repository
    """
    print(self.name)
    commits = []
    for ref in self.repo.listall_reference_objects():
      print(ref.target)
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

    print(json.dumps(commits, indent=2))