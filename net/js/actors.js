// TONK actor reference - canonical names, MITRE G-IDs, and aliases.
// Source: MITRE ATT&CK Groups (enterprise).
//
// Canonical naming (Option 2): TONK keeps its own working name as canonical.
// ONLY when TONK uses multiple names for the SAME MITRE group do those names
// collapse to the MITRE-primary name, so attribution never splits one actor.
// The MITRE G-number (mitre field) is the true identity anchor - names can be
// renamed upstream, G-numbers do not change.
//
// Scope: only NAMED actors TONK tracks that resolve to a MITRE group. Generic/
// commodity buckets (Ransomware, Conti, Emotet...) are excluded by design.
//
// Shape: ACTORS[canonicalName] = { mitre, cls, aliases[] }
// resolveActor(anyName)   -> canonical name (or input unchanged if unknown)
// actorMitreId(anyName)   -> "Gxxxx" or null
// actorLabel(anyName)     -> "Canonical (Gxxxx)" for display, or input if unknown

const ACTORS = {
  "APT10": { mitre: "G0045", cls: "apt-cn", aliases: ["Cicada", "POTASSIUM", "Stone Panda", "Red Apollo", "CVNX", "HOGFISH", "BRONZE RIVERSIDE", "menuPass"] },
  "APT28": { mitre: "G0007", cls: "apt-ru", aliases: ["IRON TWILIGHT", "SNAKEMACKEREL", "Swallowtail", "Group 74", "Sednit", "Sofacy", "Pawn Storm", "Fancy Bear", "STRONTIUM", "Tsar Team", "Threat Group-4127", "TG-4127", "Forest Blizzard", "FROZENLAKE", "GruesomeLarch"] },
  "APT29": { mitre: "G0016", cls: "apt-ru", aliases: ["IRON RITUAL", "IRON HEMLOCK", "NobleBaron", "Dark Halo", "NOBELIUM", "UNC2452", "YTTRIUM", "The Dukes", "Cozy Bear", "CozyDuke", "SolarStorm", "Blue Kitsune", "UNC3524", "Midnight Blizzard"] },
  "APT3": { mitre: "G0022", cls: "apt-cn", aliases: ["Gothic Panda", "Pirpi", "UPS Team", "Buckeye", "Threat Group-0110", "TG-0110"] },
  "APT33": { mitre: "G0064", cls: "apt-ir", aliases: ["HOLMIUM", "Elfin", "Peach Sandstorm"] },
  "APT40": { mitre: "G0065", cls: "apt-cn", aliases: ["MUDCARP", "Kryptonite Panda", "Gadolinium", "BRONZE MOHAWK", "TEMP.Jumper", "TEMP.Periscope", "Gingham Typhoon", "Leviathan"] },
  "APT41": { mitre: "G0096", cls: "apt-cn", aliases: ["Wicked Panda", "Brass Typhoon", "BARIUM"] },
  "Axiom": { mitre: "G0001", cls: "apt-mul", aliases: ["Group 72"] },
  "Dragonfly": { mitre: "G0035", cls: "apt-ru", aliases: ["TEMP.Isotope", "DYMALLOY", "Berserk Bear", "TG-4192", "Crouching Yeti", "IRON LIBERTY", "Energetic Bear", "Ghost Blizzard", "BROMINE"] },
  "FIN7": { mitre: "G0046", cls: "apt-mul", aliases: ["GOLD NIAGARA", "ITG14", "Carbon Spider", "ELBRUS", "Sangria Tempest"] },
  "HAFNIUM": { mitre: "G0125", cls: "apt-cn", aliases: ["Operation Exchange Marauder", "Silk Typhoon"] },
  "Kimsuky": { mitre: "G0094", cls: "apt-kp", aliases: ["Black Banshee", "Velvet Chollima", "Emerald Sleet", "THALLIUM", "APT43", "TA427", "Springtail", "Earth Kumiho", "PatheticSlug"] },
  "Lazarus": { mitre: "G0032", cls: "apt-kp", aliases: ["Labyrinth Chollima", "HIDDEN COBRA", "Guardians of Peace", "ZINC", "NICKEL ACADEMY", "Diamond Sleet", "Lazarus Group"] },
  "Magic Hound": { mitre: "G0059", cls: "apt-ir", aliases: ["TA453", "COBALT ILLUSION", "Charming Kitten", "ITG18", "Phosphorus", "Newscaster", "APT35", "Mint Sandstorm"] },
  "Moonstone Sleet": { mitre: "G1036", cls: "apt-kp", aliases: ["Storm-1789"] },
  "MuddyWater": { mitre: "G0069", cls: "apt-ir", aliases: ["Earth Vetala", "MERCURY", "Static Kitten", "Seedworm", "TEMP.Zagros", "Mango Sandstorm", "TA450", "MuddyKrill"] },
  "Mustang Panda": { mitre: "G0129", cls: "apt-cn", aliases: ["TA416", "RedDelta", "BRONZE PRESIDENT", "STATELY TAURUS", "FIREANT", "CAMARO DRAGON", "EARTH PRETA", "HIVE0154", "TWILL TYPHOON", "TANTALUM", "LUMINOUS MOTH", "UNC6384", "TEMP.Hex", "Red Lich", "ClumsyToad"] },
  "OilRig": { mitre: "G0049", cls: "apt-ir", aliases: ["COBALT GYPSY", "IRN2", "APT34", "Helix Kitten", "Evasive Serpens", "Hazel Sandstorm", "EUROPIUM", "ITG13", "Earth Simnavaz", "Crambus", "TA452"] },
  "Salt Typhoon": { mitre: "G1045", cls: "apt-cn", aliases: [] },
  "Sandworm": { mitre: "G0034", cls: "apt-ru", aliases: ["ELECTRUM", "Telebots", "IRON VIKING", "BlackEnergy (Group)", "Quedagh", "Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "FROZENBARENTS", "APT44", "Sandworm Team"] },
  "Scattered Spider": { mitre: "G1015", cls: "apt-mul", aliases: ["Roasted 0ktapus", "Octo Tempest", "Storm-0875", "UNC3944"] },
  "Turla": { mitre: "G0010", cls: "apt-ru", aliases: ["IRON HUNTER", "Group 88", "Waterbug", "WhiteBear", "Snake", "Krypton", "Venomous Bear", "Secret Blizzard", "BELUGASTURGEON"] },
  "Volt Typhoon": { mitre: "G1017", cls: "apt-cn", aliases: ["BRONZE SILHOUETTE", "Vanguard Panda", "DEV-0391", "UNC3236", "Voltzite", "Insidious Taurus", "DazedToad"] },
  "Winnti": { mitre: "G0044", cls: "apt-cn", aliases: ["Blackfly", "Winnti Group"] },
  "ZIRCONIUM": { mitre: "G0128", cls: "apt-cn", aliases: ["APT31", "Violet Typhoon"] },
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
