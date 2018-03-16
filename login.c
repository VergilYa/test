#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define _XOPEN_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <shadow.h>
#include <errno.h>

#define USER_LEN	16
#define PW_LEN		64

void banner (void)
{
fprintf(stdout, "[uname ent]\n");
fflush(stdout);
}

/* 检查username是否存在，不判断密码 */
struct passwd *get_input (char *buf, int type)
{
int retval = 0;
int len = type?PW_LEN:USER_LEN;
struct passwd *pw_st = NULL;
char *retry_info = type?"Password: ":"[host] login: ";

fprintf(stdout, retry_info);
fflush(stdout);

while(retval < 2) {
retval = read(0, buf, len);
if (retval > 1) {
buf[retval - 1] = 0;
if (type == 0) {
pw_st = getpwnam(buf);
if (pw_st == NULL)
retval = 0;
}
}
if (retval < 2) {
fprintf(stdout, "\nLogin incorrect\n%s", retry_info);
fflush(stdout);
}
}
return type?NULL:pw_st;
}

int check_pass (char *pw_str, struct passwd *pw)
{
char *stored_pw;
char *salt;
char *enc_pw_str;
char *delim;
struct spwd *shadow_entry;

if (pw->pw_passwd[0] == 0) {			// 无密码
return 0;
} else if (!strncmp(pw->pw_passwd, "x", 2)) {	// 影子密码
shadow_entry = getspnam(pw->pw_name);
if (shadow_entry != NULL)
stored_pw = shadow_entry->sp_pwdp;
else
perror("[Not Root?]");
} else {					// passwd直接密码
stored_pw = pw->pw_passwd;
}

if ((stored_pw[0] == '!') || (stored_pw[0] == '*'))
return -1;
/* 截出 salt 值 */
delim = strrchr(stored_pw, '$');
delim[0] = 0;
salt = stored_pw;

enc_pw_str = crypt(pw_str, salt);
delim[0] = '$';	/* 恢复 stored_pw */

if (strcmp(enc_pw_str, stored_pw))
return -1;
else
return 0;
}

int main (void)
{
int retval;
char user_str[USER_LEN];
char pw_str[PW_LEN];
struct passwd *pw;

banner();
pw = get_input(user_str, 0);
get_input(pw_str, 1);
retval = check_pass(pw_str, pw);
if (retval == 0)
printf("Login succeeded.\n");
else
printf("Login failed.\n");

return retval;
}
