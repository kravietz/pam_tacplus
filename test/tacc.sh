#!/bin/sh
/usr/local/bin/tacc --authenticate --username testuser1 --password testpass123 --server localhost --remote 5.6.7.8 --tty ttyS0 --secret testkey123 --service ppp --protocol ip --login pap
/usr/local/bin/tacc --authorize --username testuser1 --password testpass123 --server localhost --remote 5.6.7.8 --tty ttyS0 --secret testkey123 --service ppp --protocol ip --login pap
/usr/local/bin/tacc --account --username testuser1 --password testpass123 --server localhost --remote 5.6.7.8 --tty ttyS0 --secret testkey123 --service ppp --protocol ip --login pap
/usr/local/bin/tacc --authenticate --username testuser1 --password badpass --server localhost --remote 5.6.7.8 --tty ttyS0 --secret testkey123 --service ppp --protocol ip --login pap || true
/usr/local/bin/tacc --authorize --username testuser1 --password badpass --server localhost --remote 5.6.7.8 --tty ttyS0 --secret testkey123 --service ppp --protocol ip --login pap || true
/usr/local/bin/tacc --account --username testuser1 --password badpass --server localhost --remote 5.6.7.8 --tty ttyS0 --secret testkey123 --service ppp --protocol ip --login pap || true
/usr/local/bin/tacc --authenticate --username testuser1 --password testpass123 --server localhost --remote 5.6.7.8 --tty ttyS0 --secret badkey --service ppp --protocol ip --login pap || true   
/usr/local/bin/tacc --authenticate --authorize --account --username testuser1 --password testpass123 --server localhost --remote 5.6.7.8 --tty ttyS0 --secret testkey123 --service ppp --protocol ip --login pap            
- 