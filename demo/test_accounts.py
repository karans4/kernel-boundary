import tempfile,time,unittest
from pathlib import Path
from demo import accounts
class AccountTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.old=accounts.DB;accounts.DB=Path(self.tmp.name)/'accounts.db';accounts.ATTEMPTS.clear()
 def tearDown(self):accounts.DB=self.old;self.tmp.cleanup()
 def test_login_logout_and_no_plaintext_storage(self):
  result=accounts.register(dict(email='one@example.test',password='test-password-123',workspace='One'))
  self.assertEqual(accounts.authenticate(result['token'])['workspace'],'One')
  self.assertNotIn(b'test-password-123',accounts.DB.read_bytes())
  self.assertNotIn(result['token'].encode(),accounts.DB.read_bytes())
  logged=accounts.login(dict(email='one@example.test',password='test-password-123'))
  accounts.logout(logged['token']);self.assertIsNone(accounts.authenticate(logged['token']))
  with self.assertRaises(ValueError):accounts.login(dict(email='one@example.test',password='wrong-password-123'))
 def test_history_is_owner_scoped_and_persistent(self):
  one=accounts.register(dict(email='one@example.test',password='test-password-123'))['user']
  two=accounts.register(dict(email='two@example.test',password='test-password-123'))['user']
  accounts.save_run(dict(owner=one['id'],runId='run-one',status='complete',report='private'))
  self.assertEqual(accounts.history(one['id'])[0]['report'],'private')
  self.assertEqual(accounts.history(two['id']),[])
 def test_session_expiry_and_rate_limit(self):
  result=accounts.register(dict(email='one@example.test',password='test-password-123'))
  with accounts.db() as con:con.execute('UPDATE sessions SET expires=?',(time.time()-1,))
  self.assertIsNone(accounts.authenticate(result['token']))
  for i in range(4):
   with self.assertRaises(ValueError):accounts.login(dict(email='one@example.test',password='wrong-password-123'))
  with self.assertRaisesRegex(ValueError,'Too many'):accounts.login(dict(email='one@example.test',password='test-password-123'))
if __name__=='__main__':unittest.main()
