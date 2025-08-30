using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace LanProbe.Core.Analysis
{
    internal static class RouterBrandCatalog
    {
        private static readonly (string Brand, string[] Keywords, string[] Domains)[] Map =
        {
            ("Xiaomi",     new[] { "miwifi", "xiaomi" },                     new[] { "miwifi.com" }),
            ("MikroTik",   new[] { "routeros", "mikrotik" },                 new[] { "mikrotik.com" }),
            ("Ubiquiti",   new[] { "ubiquiti", "unifi", "airmax", "edgeos" },new[] { "ui.com", "ubnt.com" }),
            ("TP-Link",    new[] { "tplink", "tp-link" },                    new[] { "tplinkwifi.net" }),
            ("Keenetic",   new[] { "keenetic", "ndms" },                     new[] { "keenetic.cloud" }),
            ("ASUS",       new[] { "asuswrt", "asustek", "asus" },           new[] { "asus.com" }),
            ("D-Link",     new[] { "d-link", "dlink" },                      new[] { "dlink" }),
            ("Zyxel",      new[] { "zyxel" },                                new[] { "zyxel" }),
            ("Netgear",    new[] { "netgear", "routerlogin" },               new[] { "routerlogin.net", "routerlogin.com" }),
            ("Huawei",     new[] { "huawei", "hilink" },                     new[] { "huawei" }),
            ("ZTE",        new[] { "zte" },                                  new[] { "zte" }),
            ("Tenda",      new[] { "tenda" },                                new[] { "tendawifi.com" }),
            ("Linksys",    new[] { "linksys", "velop" },                     new[] { "linksys" }),
            ("AVM Fritz!", new[] { "fritz!box", "fritz.box", "avm" },        new[] { "fritz.box" }),
            ("Synology RT",new[] { "synology router", "sr-mr", "rt2600ac" }, new[] { "synology.com" }),
            ("OpenWrt",    new[] { "openwrt", "luci" },                      Array.Empty<string>()),
            ("DD-WRT",     new[] { "dd-wrt" },                               Array.Empty<string>()),
            ("EdgeRouter", new[] { "edgerouter", "edgeos" },                 Array.Empty<string>()),
            ("Technicolor",new[] { "technicolor" },                           Array.Empty<string>()),
            ("Sagemcom",   new[] { "sagemcom" },                              Array.Empty<string>()),
            ("Arris",      new[] { "arris" },                                 Array.Empty<string>()),
        };

        public static bool TryDetect(string haystack, out string brand)
        {
            brand = "";
            if (string.IsNullOrWhiteSpace(haystack)) return false;

            // нормализуем
            string s = haystack.ToLowerInvariant();

            // 1) По ключевым словам
            foreach (var (Brand, Keywords, _) in Map)
            {
                if (Keywords.Any(k => s.Contains(k)))
                {
                    brand = Brand;
                    return true;
                }
            }

            // 2) По доменным именам/хостам, если встречаются
            foreach (var (Brand, _, Domains) in Map)
            {
                if (Domains.Length > 0 && Domains.Any(d => s.Contains(d)))
                {
                    brand = Brand;
                    return true;
                }
            }

            // 3) эвристика по CN/Issuer «router», «gateway», «home»
            if (Regex.IsMatch(s, @"\b(router|gateway|home\.?lan|home)\b"))
            {
                brand = "Generic Router";
                return true;
            }

            return false;
        }
    }
}
