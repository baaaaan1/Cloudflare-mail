import type { NameStyle } from "@/lib/types"

const NAME_PARTS: Record<NameStyle, { first: string[]; last: string[] }> = {
  id: {
    first: [
      "aditya",
      "agung",
      "andika",
      "bagas",
      "bima",
      "dewi",
      "dimas",
      "farhan",
      "fajar",
      "fitri",
      "galih",
      "hana",
      "indah",
      "joko",
      "kurnia",
      "lina",
      "maulana",
      "nabila",
      "putra",
      "rani",
      "reza",
      "rizky",
      "salsa",
      "tiara",
      "wahyu",
      "yusuf",
    ],
    last: [
      "ananda",
      "cahaya",
      "hidayat",
      "kurniawan",
      "maharani",
      "maulana",
      "nugraha",
      "permata",
      "pratama",
      "putri",
      "ramadhan",
      "saputra",
      "setiawan",
      "syahputra",
      "wijaya",
    ],
  },
  us: {
    first: [
      "alex",
      "amelia",
      "ava",
      "benjamin",
      "charlotte",
      "daniel",
      "elijah",
      "emma",
      "ethan",
      "harper",
      "henry",
      "isabella",
      "james",
      "liam",
      "lucas",
      "mia",
      "noah",
      "olivia",
      "sophia",
      "theodore",
      "william",
      "zoe",
    ],
    last: [
      "anderson",
      "bennett",
      "brown",
      "carter",
      "cooper",
      "davis",
      "edwards",
      "garcia",
      "harris",
      "johnson",
      "martin",
      "miller",
      "mitchell",
      "roberts",
      "smith",
      "thompson",
      "wilson",
    ],
  },
}

export function randomItem<T>(items: readonly T[]): T {
  return items[Math.floor(Math.random() * items.length)] as T
}

export function createRandomLocalPart(style: NameStyle = "us") {
  const parts = NAME_PARTS[style] ?? NAME_PARTS.us
  const suffix = String(Math.floor(Math.random() * 900) + 100)
  return `${randomItem(parts.first)}.${randomItem(parts.last)}${suffix}`
}

export function validateLocalPart(value: string) {
  const localPart = value.trim()
  if (!localPart) return "Enter a name for your address."
  if (localPart.includes("@")) return "Leave the @domain part off — just enter a name."
  if (/\s/.test(localPart)) return "Names cannot contain spaces."
  if (localPart.length > 64) return "Keep the name under 64 characters."
  if (!/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(localPart)) {
    return "Use letters, numbers, dots, dashes or underscores."
  }
  if (localPart.startsWith(".") || localPart.endsWith(".") || localPart.includes("..")) {
    return "Dots cannot start, end, or repeat."
  }
  return ""
}

export const NAME_STYLE_LABELS: Record<NameStyle, string> = {
  us: "English",
  id: "Indonesian",
}
