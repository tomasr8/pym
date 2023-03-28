string = """
PAM_SUCCESS
PAM_OPEN_ERR
PAM_SYMBOL_ERR
PAM_SERVICE_ERRE
PAM_SYSTEM_ERR
PAM_BUF_ERR
PAM_PERM_DENIED
PAM_AUTH_ERR
PAM_CRED_INSUFFICIENT
PAM_AUTHINFO_UNAVAIL
PAM_USER_UNKNOWN
PAM_MAXTRIES
PAM_NEW_AUTHTOK_REQD
PAM_ACCT_EXPIRED
PAM_SESSION_ERR
PAM_CRED_UNAVAIL
PAM_CRED_EXPIRED
PAM_CRED_ERR
PAM_NO_MODULE_DATA
PAM_CONV_ERR
PAM_AUTHTOK_ERR
PAM_AUTHTOK_RECOVERY_ERR
PAM_AUTHTOK_LOCK_BUSY
PAM_AUTHTOK_DISABLE_AGING
PAM_TRY_AGAIN
PAM_IGNORE
PAM_ABORT
PAM_AUTHTOK_EXPIRED
PAM_MODULE_UNKNOWN
PAM_BAD_ITEM
PAM_CONV_AGAIN
PAM_INCOMPLETE
PAM_SILENT
PAM_DISALLOW_NULL_AUTHTOK
PAM_ESTABLISH_CRED
PAM_DELETE_CRED
PAM_REINITIALIZE_CRED
PAM_REFRESH_CRED
PAM_CHANGE_EXPIRED_AUTHTOK
PAM_PRELIM_CHECK
PAM_UPDATE_AUTHTOK
PAM_SERVICE   
PAM_USER
PAM_TTY  
PAM_RHOST
PAM_CONV
PAM_AUTHTOK
PAM_OLDAUTHTOK
PAM_RUSER
PAM_USER_PROMPT
PAM_FAIL_DELAY
PAM_XDISPLAY
PAM_XAUTHDATA
PAM_AUTHTOK_TYPE
PAM_PROMPT_ECHO_OFF
PAM_PROMPT_ECHO_ON
PAM_ERROR_MSG
PAM_TEXT_INFO 
PAM_RADIO_TYPE
PAM_BINARY_PROMPT
PAM_DATA_REPLACE
PAM_DATA_SILENT
""".strip()


longest = max(len(line) for line in string.split("\n"))
print(longest)

# out = '\n'.join([f"{line}{((longest+1)-len(line))*' '}= {line}" for line in string.split("\n")])
# print(out)

out = '\n'.join([f"{line}{((longest+1)-len(line))*' '}: int" for line in string.split("\n")])
print(out)