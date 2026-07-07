// Aggregates all misconfiguration categories into one database.
// Loaded by popup/popup.html (extension page).

(function () {
  // Note: the category files declare arrays using top-level `const`.
  // Those bindings are visible across scripts but are NOT properties on globalThis.
  const missing = [
    ["category1_TransportAndHeaders", typeof category1_TransportAndHeaders === "undefined"],
    ["category2_AuthenticationAndSession", typeof category2_AuthenticationAndSession === "undefined"],
    ["category3_InputValidationInjection", typeof category3_InputValidationInjection === "undefined"],
    ["category4_AccessControl", typeof category4_AccessControl === "undefined"],
    ["category5_CryptographyDataProtection", typeof category5_CryptographyDataProtection === "undefined"],
    ["category6_APIWebServices", typeof category6_APIWebServices === "undefined"],
    ["category7_ClientSideSecurity", typeof category7_ClientSideSecurity === "undefined"],
    ["category8_ConfigurationDeployment", typeof category8_ConfigurationDeployment === "undefined"],
    ["category9_ThirdPartyDependencies", typeof category9_ThirdPartyDependencies === "undefined"],
    ["category10_InformationDisclosure", typeof category10_InformationDisclosure === "undefined"]
  ]
    .filter(([, isMissing]) => isMissing)
    .map(([name]) => name);

  if (missing.length > 0) {
    console.warn("Misconfiguration DB missing arrays:", missing);
  }

  const all = []
    .concat(typeof category1_TransportAndHeaders === "undefined" ? [] : category1_TransportAndHeaders)
    .concat(typeof category2_AuthenticationAndSession === "undefined" ? [] : category2_AuthenticationAndSession)
    .concat(typeof category3_InputValidationInjection === "undefined" ? [] : category3_InputValidationInjection)
    .concat(typeof category4_AccessControl === "undefined" ? [] : category4_AccessControl)
    .concat(typeof category5_CryptographyDataProtection === "undefined" ? [] : category5_CryptographyDataProtection)
    .concat(typeof category6_APIWebServices === "undefined" ? [] : category6_APIWebServices)
    .concat(typeof category7_ClientSideSecurity === "undefined" ? [] : category7_ClientSideSecurity)
    .concat(typeof category8_ConfigurationDeployment === "undefined" ? [] : category8_ConfigurationDeployment)
    .concat(typeof category9_ThirdPartyDependencies === "undefined" ? [] : category9_ThirdPartyDependencies)
    .concat(typeof category10_InformationDisclosure === "undefined" ? [] : category10_InformationDisclosure);

  const byId = new Map();
  const byCheckFunction = new Map();

  for (const item of all) {
    if (item && typeof item.id === "number") {
      byId.set(item.id, item);
    }
    if (item && item.checkFunction) {
      const key = String(item.checkFunction);
      const existing = byCheckFunction.get(key);
      if (existing) existing.push(item);
      else byCheckFunction.set(key, [item]);
    }
  }

  globalThis.MISCONFIG_DB = {
    total: all.length,
    all,
    byId,
    byCheckFunction
  };
})();
