// TONK actor reference - canonical names, MITRE G-IDs, and aliases.
// Source: MITRE ATT&CK Groups (enterprise).
//
// Canonical naming: TONK keeps its own working name as canonical.
// ONLY when TONK uses multiple names for the SAME MITRE group do those names
// collapse to the MITRE-primary name, so attribution never splits one actor.
// The MITRE G-number (mitre field) is the true identity anchor - names can be
// renamed upstream, G-numbers do not change.
//
// Scope: only NAMED actors TONK tracks that resolve to a MITRE group. Generic/
// commodity buckets (Ransomware, Cobalt Strike, Emotet...) are excluded by design.
//
// Shape: ACTORS[canonicalName] = { mitre, cls, aliases[] }
// resolveActor(anyName)   -> canonical name (or input unchanged if unknown)
// actorMitreId(anyName)   -> "Gxxxx" or null
// actorLabel(anyName)     -> "Canonical (Gxxxx)" for display, or input if unknown

const ACTORS = {
  "APT10": { mitre: "G0045", cls: "apt-cn", aliases: ["Cicada", "POTASSIUM", "Stone Panda", "Red Apollo", "CVNX", "HOGFISH", "BRONZE RIVERSIDE", "menuPass"] },
  "APT28": { mitre: "G0007", cls: "apt-ru", aliases: ["IRON TWILIGHT", "SNAKEMACKEREL", "Swallowtail", "Group 74", "Sednit", "Sofacy", "Pawn Storm", "Fancy Bear", "STRONTIUM", "Tsar Team", "Threat Group-4127", "TG-4127", "Forest Blizzard", "FROZENLAKE", "GruesomeLarch"] },
  "APT29": { mitre: "G0016", cls: "apt-ru", aliases: ["IRON RITUAL", "IRON HEMLOCK", "NobleBaron", "Dark Halo", "NOBELIUM", "UNC2452", "YTTRIUM", "The Dukes", "Cozy Bear", "CozyDuke", "SolarStorm", "Blue Kitsune", "UNC3524", "Midnight Blizzard"] },
  "APT32": { mitre: "G0050", cls: "apt-cn", aliases: ["OceanLotus", "SeaLotus", "BISMUTH", "Canvas Cyclone", "APT-C-00", "Ocean Buffalo"] },
  "APT33": { mitre: "G0064", cls: "apt-ir", aliases: ["HOLMIUM", "Elfin", "Peach Sandstorm"] },
  "APT41": { mitre: "G0096", cls: "apt-cn", aliases: ["Wicked Panda", "Brass Typhoon", "BARIUM"] },
  "APT5": { mitre: "G1023", cls: "apt-cn", aliases: ["Keyhole Panda", "MANGANESE", "Mulberry Typhoon"] },
  "BPFDoor": { mitre: null, cls: "apt-cn", aliases: ["Red Menshen", "Red Dev 18", "JustForFun"] },
  "Ebury": { mitre: null, cls: "apt-ru", aliases: ["Windigo", "Operation Windigo"] },
  "FIN6": { mitre: "G0037", cls: "apt-mul", aliases: ["Skeleton Spider", "ITG08", "Magecart Group 6"] },
  "FIN7": { mitre: "G0046", cls: "apt-mul", aliases: ["GOLD NIAGARA", "ITG14", "Carbon Spider", "ELBRUS", "Sangria Tempest"] },
  "Gamaredon": { mitre: "G0047", cls: "apt-ru", aliases: ["Primitive Bear", "ACTINIUM", "Aqua Blizzard", "Armageddon", "Shuckworm"] },
  "HAFNIUM": { mitre: "G0125", cls: "apt-cn", aliases: ["Operation Exchange Marauder", "Silk Typhoon"] },
  "Kimsuky": { mitre: "G0094", cls: "apt-kp", aliases: ["Black Banshee", "Velvet Chollima", "Emerald Sleet", "THALLIUM", "APT43", "TA427", "Springtail", "Earth Kumiho", "Gomir"] },
  "Lazarus": { mitre: "G0032", cls: "apt-kp", aliases: ["Labyrinth Chollima", "HIDDEN COBRA", "Guardians of Peace", "ZINC", "NICKEL ACADEMY", "Diamond Sleet", "Lazarus Group", "APT38", "BeagleBoyz", "BlueNoroff"] },
  "Magic Hound": { mitre: "G0059", cls: "apt-ir", aliases: ["TA453", "COBALT ILLUSION", "Charming Kitten", "ITG18", "Phosphorus", "Newscaster", "APT35", "Mint Sandstorm"] },
  "MuddyWater": { mitre: "G0069", cls: "apt-ir", aliases: ["Earth Vetala", "MERCURY", "Static Kitten", "Seedworm", "TEMP.Zagros", "Mango Sandstorm", "TA450"] },
  "Mustang Panda": { mitre: "G0129", cls: "apt-cn", aliases: ["TA416", "RedDelta", "BRONZE PRESIDENT", "STATELY TAURUS", "EARTH PRETA", "TWILL TYPHOON", "LUMINOUS MOTH"] },
  "OilRig": { mitre: "G0049", cls: "apt-ir", aliases: ["COBALT GYPSY", "IRN2", "APT34", "Helix Kitten", "Evasive Serpens", "Hazel Sandstorm", "EUROPIUM", "ITG13", "Earth Simnavaz", "Crambus"] },
  "APT39": { mitre: "G0087", cls: "apt-ir", aliases: ["Chafer", "REMIX KITTEN", "Rana Intelligence"] },
  "Salt Typhoon": { mitre: "G1045", cls: "apt-cn", aliases: ["GhostEmperor", "FamousSparrow", "Earth Estries"] },
  "Sandworm": { mitre: "G0034", cls: "apt-ru", aliases: ["ELECTRUM", "Telebots", "IRON VIKING", "BlackEnergy (Group)", "Quedagh", "Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "FROZENBARENTS", "APT44", "Sandworm Team"] },
  "Scattered Spider": { mitre: "G1015", cls: "apt-mul", aliases: ["Roasted 0ktapus", "Octo Tempest", "Storm-0875", "UNC3944"] },
  "TA505": { mitre: "G0092", cls: "apt-mul", aliases: ["GOLD TAHOE", "Hive0065", "SectorJ04", "Graceful Spider"] },
  "TeamTNT": { mitre: null, cls: "apt-mul", aliases: ["TNT", "Hildegard operators"] },
  "Turla": { mitre: "G0010", cls: "apt-ru", aliases: ["IRON HUNTER", "Group 88", "Waterbug", "WhiteBear", "Snake", "Krypton", "Venomous Bear", "Secret Blizzard", "BELUGASTURGEON"] },
  "Volt Typhoon": { mitre: "G1017", cls: "apt-cn", aliases: ["BRONZE SILHOUETTE", "Vanguard Panda", "DEV-0391", "UNC3236", "Voltzite", "Insidious Taurus", "DazedToad"] },
  "Winnti": { mitre: "G0044", cls: "apt-cn", aliases: ["Blackfly", "Winnti Group"] },
  "Andariel": { mitre: "G0138", cls: "apt-kp", aliases: ["Stonefly", "Onyx Sleet", "PLUTONIUM", "Silent Chollima"] },
};

// Reverse index: normalized alias/name -> canonical. Built at load.
const ACTOR_ALIAS = (() => {
  const idx = {};
  const norm = s => String(s).toLowerCase().replace(/[^a-z0-9]/g, "");
  for (const [canon, rec] of Object.entries(ACTORS)) {
    idx[norm(canon)] = canon;
    for (const a of rec.aliases) idx[norm(a)] = canon;
  }
  return idx;
})();

function resolveActor(name) {
  if (!name) return name;
  const key = String(name).toLowerCase().replace(/[^a-z0-9]/g, "");
  return ACTOR_ALIAS[key] || name;
}

// MITRE G-number for any name/alias, or null if not a tracked named actor.
function actorMitreId(name) {
  const c = resolveActor(name);
  return (ACTORS[c] && ACTORS[c].mitre) || null;
}

// Display label: "Canonical (Gxxxx)" when known, else the input unchanged.
function actorLabel(name) {
  const c = resolveActor(name);
  const rec = ACTORS[c];
  return rec ? c + " (" + rec.mitre + ")" : name;
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { ACTORS, ACTOR_ALIAS, resolveActor, actorMitreId, actorLabel };
}
