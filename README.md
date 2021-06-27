# Shared-FlushFileBuffers-Communication
Cool kernel communication method.

unknowncheats post: https://www.unknowncheats.me/forum/anti-cheat-bypass/448472-shared-buffer-flushfilebuffers-communication-driverbase.html#post3110503

Hello my friends, i would like to share a cool kernel communication method.
This method abuse FlushFileBuffers because it calls in kernel IRP_MJ_FLUSH_BUFFERS and this is a sexy MajorFunction you can hook without any issues. Iv not tested this on any anticheat but far as i know IRP_MJ_FLUSH_BUFFERS is not checked for most drivers!
Even iv its getting checked with basic checks we can getaround this by hooking the MajorFunction and set the hook to a other unknown MajorFunction of a legit driver that we also hooked. 
I know shared buffer stuff is nothing new but the idea of processing the call without any running thread or something else is quite cool ;)

atm this is not thread safe, but you can get it done with something like this:
https://www.unknowncheats.me/forum/c-and-c-/391107-discuss-shared-buffer-synchonization.html

