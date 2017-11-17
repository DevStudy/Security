// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Microsoft.AspNetCore.CookiePolicy
{
    internal class ResponseCookiesWrapper : IResponseCookies, IPersistencePermissionFeature
    {
        private bool? _isPermissionNeeded;
        private bool? _hasPermission;

        public ResponseCookiesWrapper(HttpContext context, CookiePolicyOptions options, IResponseCookiesFeature feature)
        {
            Context = context;
            Feature = feature;
            Options = options;
        }

        private HttpContext Context { get; }

        private IResponseCookiesFeature Feature { get; }

        private IResponseCookies Cookies => Feature.Cookies;

        private CookiePolicyOptions Options { get; }

        public bool IsPermissionNeeded
        {
            get
            {
                if (!_isPermissionNeeded.HasValue)
                {
                    _isPermissionNeeded = Options.CheckPersistencePolicyNeeded == null ? false
                        : Options.CheckPersistencePolicyNeeded(Context);
                }

                return _isPermissionNeeded.Value;
            }
        }

        public bool HasPermission
        {
            get
            {
                if (!_hasPermission.HasValue)
                {
                    var cookie = Context.Request.Cookies[Options.PersistenceCookie.Name];
                    _hasPermission = string.Equals(cookie, "yes");
                }

                return _hasPermission.Value;
            }
        }
        
        public bool CanPersist => !IsPermissionNeeded || HasPermission;

        public void GrantPermission()
        {
            if (!HasPermission && !Context.Response.HasStarted)
            {
                _hasPermission = true;
                var cookieOptions = Options.PersistenceCookie.Build(Context);
                // Note policy will be applied. What purpose should be used?
                // We don't want to bypass policy because we want HttpOnly, Secure, etc. to apply.
                Append(Options.PersistenceCookie.Name, "yes", cookieOptions);
            }
        }

        public void WithdrawPermission()
        {
            if (CanPersist && !Context.Response.HasStarted)
            {
                var cookieOptions = Options.PersistenceCookie.Build(Context);
                Delete(Options.PersistenceCookie.Name, cookieOptions);
            }
            _hasPermission = false;
        }

        private bool CheckPolicyRequired()
        {
            return !CanPersist
                || Options.MinimumSameSitePolicy != SameSiteMode.None
                || Options.HttpOnly != HttpOnlyPolicy.None
                || Options.Secure != CookieSecurePolicy.None;
        }

        public void Append(string key, string value)
        {
            if (CheckPolicyRequired() || Options.OnAppendCookie != null)
            {
                Append(key, value, new CookieOptions());
            }
            else
            {
                Cookies.Append(key, value);
            }
        }

        public void Append(string key, string value, CookieOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            var canPersist = CanPersist;
            // TODO: Default persist policy?
            ApplyPolicy(options);
            if (Options.OnAppendCookie != null)
            {
                var context = new AppendCookieContext(Context, options, key, value)
                {
                    IsPermissionNeeded = IsPermissionNeeded,
                    HasPermission = HasPermission,
                    CanPersist = canPersist,
                };
                Options.OnAppendCookie(context);

                key = context.CookieName;
                value = context.CookieValue;
                canPersist = context.CanPersist;
            }

            if (canPersist)
            {
                Cookies.Append(key, value, options);
            }
        }

        public void Delete(string key)
        {
            if (CheckPolicyRequired() || Options.OnDeleteCookie != null)
            {
                Delete(key, new CookieOptions());
            }
            else
            {
                Cookies.Delete(key);
            }
        }

        public void Delete(string key, CookieOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            // Assume you can always delete cookies unless directly overridden in the user event.
            var canPersist = true;
            // TODO: Default persist policy?
            ApplyPolicy(options);
            if (Options.OnDeleteCookie != null)
            {
                var context = new DeleteCookieContext(Context, options, key)
                {
                    IsPermissionNeeded = IsPermissionNeeded,
                    HasPermission = HasPermission,
                    CanPersist = canPersist,
                };
                Options.OnDeleteCookie(context);

                key = context.CookieName;
                canPersist = context.CanPersist;
            }

            if (canPersist)
            {
                Cookies.Delete(key, options);
            }
        }

        private void ApplyPolicy(CookieOptions options)
        {
            switch (Options.Secure)
            {
                case CookieSecurePolicy.Always:
                    options.Secure = true;
                    break;
                case CookieSecurePolicy.SameAsRequest:
                    options.Secure = Context.Request.IsHttps;
                    break;
                case CookieSecurePolicy.None:
                    break;
                default:
                    throw new InvalidOperationException();
            }
            switch (Options.MinimumSameSitePolicy)
            {
                case SameSiteMode.None:
                    break;
                case SameSiteMode.Lax:
                    if (options.SameSite == SameSiteMode.None)
                    {
                        options.SameSite = SameSiteMode.Lax;
                    }
                    break;
                case SameSiteMode.Strict:
                    options.SameSite = SameSiteMode.Strict;
                    break;
                default:
                    throw new InvalidOperationException($"Unrecognized {nameof(SameSiteMode)} value {Options.MinimumSameSitePolicy.ToString()}");
            }
            switch (Options.HttpOnly)
            {
                case HttpOnlyPolicy.Always:
                    options.HttpOnly = true;
                    break;
                case HttpOnlyPolicy.None:
                    break;
                default:
                    throw new InvalidOperationException($"Unrecognized {nameof(HttpOnlyPolicy)} value {Options.HttpOnly.ToString()}");
            }
        }
    }
}