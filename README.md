# Xdecrypt

Xshell Xftp password recovery

## Usage

```
import "github.com/qnfm/Xshelldecrypt"

Call the Recovery(name, sid, pwd string) function with current user information
```

name, sid can be dumped via 
```
$ whoami /user 
```
	name := "User name" //Current User Name without domain
	sid := "S-1-8-14-1473199394-147319939-1473199394-5254" // current SID
pwd is base64 encoded password in section [CONNECTION:AUTHENTICATION] (assume xshell version is 7)



```
$ whoami /user
USER INFORMATION
----------------

User Name            SID
==================== =============================================
domain\username      sid
```