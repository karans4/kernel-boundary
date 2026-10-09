import unittest
from demo.workspace import validate
class WorkspaceInputTests(unittest.TestCase):
    def test_public_repository_normalization(self):
        for value in ('owner/repo','https://github.com/owner/repo','https://github.com/owner/repo.git'):
            self.assertEqual(validate(dict(repository=value,task='Review security risks'))['repository'],'owner/repo')
    def test_reject_non_github_and_commands(self):
        for value in ('file:///etc/shadow','https://localhost/repo','https://evil.test/a/b','owner/repo;sh','https://github.com/a/../b'):
            with self.assertRaises(ValueError): validate(dict(repository=value,task='Review security risks'))
    def test_no_arbitrary_execution_fields(self):
        with self.assertRaises(ValueError): validate(dict(repository='a/b',task='Review security risks',command='id'))
        with self.assertRaises(ValueError): validate(dict(repository='a/b',task='Review security risks',boundaryTests='yes'))
if __name__=='__main__': unittest.main()
