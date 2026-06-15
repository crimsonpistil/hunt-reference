// ── HOST REFERENCE - actors.js ──
// Threat actor catalog with alias resolution for host-based detection.
// Loaded before core.js. Provides THREAT_ACTORS map and resolveActorQuery().

const THREAT_ACTORS = {

  // ═══════════════════════════════════════════════
  //  RUSSIA (apt-ru)
  // ═══════════════════════════════════════════════

  "APT28": {
    aliases: ["Fancy Bear","STRONTIUM","Forest Blizzard","Sofacy","Sednit","Pawn Storm","TG-4127","Group 74","Tsar Team","ITG05","TAG-0700","BlueDelta","GruesomeLarch"],
    cls: "apt-ru",
    mitre: "G0007",
    origin: "Russia (GRU Unit 26165)"
  },
  "APT29": {
    aliases: ["Cozy Bear","NOBELIUM","Midnight Blizzard","The Dukes","YTTRIUM","CozyDuke","Dark Halo","StellarParticle","UNC2452","Cloaked Ursa","BlueBravo","ITG11","TAG-0102"],
    cls: "apt-ru",
    mitre: "G0016",
    origin: "Russia (SVR)"
  },
  "Sandworm": {
    aliases: ["Voodoo Bear","IRIDIUM","Seashell Blizzard","Telebots","ELECTRUM","Iron Viking","BlackEnergy Group","Sandworm Team","UAC-0082","APT44"],
    cls: "apt-ru",
    mitre: "G0034",
    origin: "Russia (GRU Unit 74455)"
  },
  "Turla": {
    aliases: ["Snake","Venomous Bear","KRYPTON","Secret Blizzard","Uroburos","Waterbug","WhiteBear","Iron Hunter","Pensive Ursa","ITG12","TAG-0530","Group 88"],
    cls: "apt-ru",
    mitre: "G0010",
    origin: "Russia (FSB Center 16)"
  },
  "Gamaredon": {
    aliases: ["Primitive Bear","ACTINIUM","Aqua Blizzard","Armageddon","Shuckworm","UAC-0010","SectorC08","BlueAlpha","TAG-0631"],
    cls: "apt-ru",
    mitre: "G0047",
    origin: "Russia (FSB Crimea)"
  },

  // ═══════════════════════════════════════════════
  //  CHINA (apt-cn)
  // ═══════════════════════════════════════════════

  "APT41": {
    aliases: ["Winnti","Double Dragon","BARIUM","Brass Typhoon","Wicked Panda","TG-2633","RedGolf","Earth Baku","TAG-0822","Blackfly"],
    cls: "apt-cn",
    mitre: "G0096",
    origin: "China (MSS / Chengdu 404)"
  },
  "APT10": {
    aliases: ["Stone Panda","POTASSIUM","Cicada","MenuPass","Red Apollo","CVNX","Cloud Hopper","ITG01","TAG-0457"],
    cls: "apt-cn",
    mitre: "G0045",
    origin: "China (MSS Tianjin)"
  },
  "APT1": {
    aliases: ["Comment Crew","COPPER","PLA Unit 61398","Comment Panda","TG-8223","GIF89a","BrownFox"],
    cls: "apt-cn",
    mitre: "G0006",
    origin: "China (PLA Unit 61398)"
  },
  "Mustang Panda": {
    aliases: ["BRONZE PRESIDENT","Stately Taurus","RedDelta","Earth Preta","TA416","LuminousMoth","Camaro Dragon","TAG-0622"],
    cls: "apt-cn",
    mitre: "G0129",
    origin: "China"
  },
  "APT5": {
    aliases: ["Keyhole Panda","MANGANESE","Mulberry Typhoon","UNC2630","TAG-0501"],
    cls: "apt-cn",
    mitre: "G1023",
    origin: "China (MSS)"
  },
  "APT32": {
    aliases: ["OceanLotus","SeaLotus","BISMUTH","Canvas Cyclone","APT-C-00","Ocean Buffalo","TAG-0424"],
    cls: "apt-cn",
    mitre: "G0050",
    origin: "Vietnam"
  },
  "Volt Typhoon": {
    aliases: ["BRONZE SILHOUETTE","Vanguard Panda","DEV-0391","Insidious Taurus","UNC3236","TAG-0897"],
    cls: "apt-cn",
    mitre: "G1017",
    origin: "China (PLA)"
  },
  "Salt Typhoon": {
    aliases: ["GhostEmperor","FamousSparrow","Earth Estries","UNC2286","TAG-0956"],
    cls: "apt-cn",
    mitre: "G1045",
    origin: "China (MSS)"
  },
  "HAFNIUM": {
    aliases: ["Silk Typhoon","UNC26198","TAG-0438"],
    cls: "apt-cn",
    mitre: "G0125",
    origin: "China"
  },
  "Flax Typhoon": {
    aliases: ["Ethereal Panda","Storm-0919","TAG-0951"],
    cls: "apt-cn",
    mitre: "G1042",
    origin: "China"
  },

  // ═══════════════════════════════════════════════
  //  NORTH KOREA (apt-kp)
  // ═══════════════════════════════════════════════

  "Lazarus": {
    aliases: ["Lazarus Group","HIDDEN COBRA","Diamond Sleet","ZINC","Labyrinth Chollima","APT38","BeagleBoyz","BlueNoroff","Sapphire Sleet","Citrine Sleet","Moonstone Sleet","Jade Sleet","TraderTraitor","UNC4736","TAG-0711"],
    cls: "apt-kp",
    mitre: "G0032",
    origin: "North Korea (RGB)"
  },
  "Kimsuky": {
    aliases: ["Velvet Chollima","THALLIUM","Emerald Sleet","APT43","Springtail","Black Banshee","TA427","ITG16","TAG-0782","Gomir"],
    cls: "apt-kp",
    mitre: "G0094",
    origin: "North Korea (RGB)"
  },
  "Andariel": {
    aliases: ["Stonefly","Onyx Sleet","PLUTONIUM","Silent Chollima","DarkSeoul","TAG-0783"],
    cls: "apt-kp",
    mitre: "G0138",
    origin: "North Korea (RGB 3rd Bureau)"
  },

  // ═══════════════════════════════════════════════
  //  IRAN (apt-ir)
  // ═══════════════════════════════════════════════

  "APT33": {
    aliases: ["Elfin","HOLMIUM","Peach Sandstorm","Refined Kitten","Magnallium","TAG-0335"],
    cls: "apt-ir",
    mitre: "G0064",
    origin: "Iran (IRGC)"
  },
  "APT34": {
    aliases: ["OilRig","CHRYSENE","Hazel Sandstorm","Helix Kitten","IRN2","Crambus","ITG13","TAG-0341","Earth Simnavaz"],
    cls: "apt-ir",
    mitre: "G0049",
    origin: "Iran (MOIS)"
  },
  "APT35": {
    aliases: ["Charming Kitten","PHOSPHORUS","Mint Sandstorm","Newscaster","Ajax Security Team","TA453","ITG18","TAG-0356"],
    cls: "apt-ir",
    mitre: "G0059",
    origin: "Iran (IRGC-IO)"
  },
  "APT39": {
    aliases: ["Chafer","REMIX KITTEN","Rana Intelligence","TAG-0391"],
    cls: "apt-ir",
    mitre: "G0087",
    origin: "Iran (MOIS)"
  },
  "MuddyWater": {
    aliases: ["MERCURY","Mango Sandstorm","Static Kitten","Seedworm","TEMP.Zagros","Earth Vetala","ITG17","TAG-0411"],
    cls: "apt-ir",
    mitre: "G0069",
    origin: "Iran (MOIS)"
  },
  "CyberAv3ngers": {
    aliases: ["IRGC-CEC","Storm-0784"],
    cls: "apt-ir",
    mitre: "",
    origin: "Iran (IRGC-CEC)"
  },

  // ═══════════════════════════════════════════════
  //  CRIMINAL / MULTI (apt-mul)
  // ═══════════════════════════════════════════════

  "FIN6": {
    aliases: ["Skeleton Spider","ITG08","Magecart Group 6","TAG-0661"],
    cls: "apt-mul",
    mitre: "G0037",
    origin: "Criminal"
  },
  "FIN7": {
    aliases: ["Sangria Tempest","GOLD NIAGARA","Carbon Spider","ITG14","Carbanak Group","TAG-0672"],
    cls: "apt-mul",
    mitre: "G0046",
    origin: "Criminal"
  },
  "TA505": {
    aliases: ["GOLD TAHOE","Hive0065","SectorJ04","Graceful Spider","CL0P operators"],
    cls: "apt-mul",
    mitre: "G0092",
    origin: "Criminal"
  },
  "TeamTNT": {
    aliases: ["TNT","Hildegard operators"],
    cls: "apt-mul",
    mitre: "",
    origin: "Criminal (cloud/container)"
  },
  "Scattered Spider": {
    aliases: ["Roasted 0ktapus","UNC3944","Star Fraud","Octo Tempest","Scatter Swine","Muddled Libra"],
    cls: "apt-mul",
    mitre: "G1015",
    origin: "Criminal"
  },

  // ═══════════════════════════════════════════════
  //  MALWARE / TOOLS (searchable as actors)
  // ═══════════════════════════════════════════════

  "PlugX": {
    aliases: ["Korplug","Destroy RAT","Sogu","THOR"],
    cls: "apt-cn",
    mitre: "S0013",
    origin: "China-nexus tooling"
  },
  "ShadowPad": {
    aliases: ["PoisonPlug"],
    cls: "apt-cn",
    mitre: "S0596",
    origin: "China-nexus tooling"
  },
  "Cobalt Strike": {
    aliases: ["CobaltStrike","CS Beacon","Beacon"],
    cls: "apt-mul",
    mitre: "S0154",
    origin: "Red team / criminal tooling"
  },
  "BPFDoor": {
    aliases: ["Red Menshen","Red Dev 18","JustForFun"],
    cls: "apt-cn",
    mitre: "",
    origin: "China-nexus backdoor"
  },
  "Ebury": {
    aliases: ["Windigo","Operation Windigo"],
    cls: "apt-ru",
    mitre: "",
    origin: "Russian criminal (credential theft)"
  }
};

// ── REVERSE INDEX ──
// Maps every alias (lowercased) back to its canonical name.
const ACTOR_ALIAS_MAP = {};
Object.entries(THREAT_ACTORS).forEach(([canonical, info]) => {
  const lc = canonical.toLowerCase();
  ACTOR_ALIAS_MAP[lc] = canonical;
  (info.aliases || []).forEach(alias => {
    ACTOR_ALIAS_MAP[alias.toLowerCase()] = canonical;
  });
});

/**
 * Given a search query fragment, return all canonical actor names
 * whose name or any alias contains the query (case-insensitive).
 * Used by core.js to expand apt-search matches.
 */
function resolveActorQuery(query) {
  if (!query) return [];
  const q = query.toLowerCase().trim();
  if (!q) return [];
  const hits = new Set();
  for (const [alias, canonical] of Object.entries(ACTOR_ALIAS_MAP)) {
    if (alias.includes(q)) {
      hits.add(canonical);
    }
  }
  return [...hits];
}

/**
 * Given a canonical actor name from an apt[] entry, return all
 * searchable strings (canonical + aliases) for indexing.
 * Used by core.js when building the searchText dataset.
 */
function getActorSearchTerms(name) {
  if (!name) return '';
  const info = THREAT_ACTORS[name];
  if (!info) return name;
  return [name, ...(info.aliases || [])].join(' ');
}
