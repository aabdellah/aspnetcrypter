// System.Web.Security.FormsAuthenticationTicket
using System;
using System.Runtime.Serialization;
using System.Web.Security;

[Serializable]
public sealed class FormsAuthenticationTicket
{
    private int _Version;

    private string _Name;

    private DateTime _Expiration;

    private DateTime _IssueDate;

    private bool _IsPersistent;

    private string _UserData;

    private string _CookiePath;

    [OptionalField(VersionAdded = 2)]
    private int _InternalVersion;

    [OptionalField(VersionAdded = 2)]
    private byte[] _InternalData;

    [NonSerialized]
    private bool _ExpirationUtcHasValue;

    [NonSerialized]
    private DateTime _ExpirationUtc;

    [NonSerialized]
    private bool _IssueDateUtcHasValue;

    [NonSerialized]
    private DateTime _IssueDateUtc;

    public int Version => _Version;

    public string Name => _Name;

    public DateTime Expiration => _Expiration;

    public DateTime IssueDate => _IssueDate;

    public bool IsPersistent => _IsPersistent;

    public bool Expired => ExpirationUtc < DateTime.UtcNow;

    public string UserData => _UserData;

    public string CookiePath => _CookiePath;

    internal DateTime ExpirationUtc
    {
        get
        {
            if (!_ExpirationUtcHasValue)
            {
                return Expiration.ToUniversalTime();
            }
            return _ExpirationUtc;
        }
    }

    internal DateTime IssueDateUtc
    {
        get
        {
            if (!_IssueDateUtcHasValue)
            {
                return IssueDate.ToUniversalTime();
            }
            return _IssueDateUtc;
        }
    }

    public FormsAuthenticationTicket(int version, string name, DateTime issueDate, DateTime expiration, bool isPersistent, string userData)
    {
        _Version = version;
        _Name = name;
        _Expiration = expiration;
        _IssueDate = issueDate;
        _IsPersistent = isPersistent;
        _UserData = userData;
        _CookiePath = FormsAuthentication.FormsCookiePath;
    }

    public FormsAuthenticationTicket(int version, string name, DateTime issueDate, DateTime expiration, bool isPersistent, string userData, string cookiePath)
    {
        _Version = version;
        _Name = name;
        _Expiration = expiration;
        _IssueDate = issueDate;
        _IsPersistent = isPersistent;
        _UserData = userData;
        _CookiePath = cookiePath;
    }

    public FormsAuthenticationTicket(string name, bool isPersistent, int timeout)
    {
        _Version = 2;
        _Name = name;
        _IssueDateUtcHasValue = true;
        _IssueDateUtc = DateTime.UtcNow;
        _IssueDate = DateTime.Now;
        _IsPersistent = isPersistent;
        _UserData = "";
        _ExpirationUtcHasValue = true;
        _ExpirationUtc = _IssueDateUtc.AddMinutes(timeout);
        _Expiration = _IssueDate.AddMinutes(timeout);
        _CookiePath = FormsAuthentication.FormsCookiePath;
    }

    internal static FormsAuthenticationTicket FromUtc(int version, string name, DateTime issueDateUtc, DateTime expirationUtc, bool isPersistent, string userData, string cookiePath)
    {
        FormsAuthenticationTicket formsAuthenticationTicket = new FormsAuthenticationTicket(version, name, issueDateUtc.ToLocalTime(), expirationUtc.ToLocalTime(), isPersistent, userData, cookiePath);
        formsAuthenticationTicket._IssueDateUtcHasValue = true;
        formsAuthenticationTicket._IssueDateUtc = issueDateUtc;
        formsAuthenticationTicket._ExpirationUtcHasValue = true;
        formsAuthenticationTicket._ExpirationUtc = expirationUtc;
        return formsAuthenticationTicket;
    }
}
