// The maker behind a MAC address in plain words ("Intel", "ABUS", "TP-Link")
// instead of the IEEE register's legal name ("Intel Corporate",
// "TP-LINK CORPORATION PTE. LTD."). Shared by the server and the page.
const BRANDS: [RegExp, string][] = [
  [/^proxmox/i, 'Proxmox VM'],
  [/^intel/i, 'Intel'],
  [/^abus/i, 'ABUS'],
  [/tp-?link/i, 'TP-Link'],
  [/zyxel/i, 'Zyxel'],
  [/asustek|^asus/i, 'ASUS'],
  [/raspberry/i, 'Raspberry Pi'],
  [/cloud network technology|hon hai|foxconn/i, 'Foxconn'],
  [/universal global scientific/i, 'USI'],
  [/^apple/i, 'Apple'],
  [/samsung/i, 'Samsung'],
  [/huawei/i, 'Huawei'],
  [/xiaomi/i, 'Xiaomi'],
  [/google/i, 'Google'],
  [/amazon/i, 'Amazon'],
  [/sonos/i, 'Sonos'],
  [/hewlett|^hp inc|^hp /i, 'HP'],
  [/dell/i, 'Dell'],
  [/lenovo/i, 'Lenovo'],
  [/liteon|lite-on/i, 'Lite-On'],
  [/realtek/i, 'Realtek'],
  [/micro-star|^msi/i, 'MSI'],
  [/gigabyte|giga-byte/i, 'Gigabyte'],
  [/azurewave/i, 'AzureWave'],
  [/espressif/i, 'Espressif (IoT)'],
  [/murata/i, 'Murata'],
  [/ubiquiti/i, 'Ubiquiti'],
  [/netgear/i, 'Netgear'],
  [/cisco/i, 'Cisco'],
  [/d-link/i, 'D-Link'],
  [/hikvision/i, 'Hikvision'],
  [/dahua/i, 'Dahua'],
  [/synology/i, 'Synology'],
  [/qnap/i, 'QNAP'],
  [/brother/i, 'Brother'],
  [/canon/i, 'Canon'],
  [/epson/i, 'Epson'],
  [/vmware/i, 'VMware VM'],
  [/microsoft/i, 'Microsoft'],
]
const NOISE = /\b(corporat(e|ion)|corp|inc|incorporated|ltd|limited|llc|gmbh|co|kg|ag|sa|s\.?a\.?s|pte|plc|bv|b\.v|oy|ab|technolog(y|ies)|communications?|electronics?|industrial|international|computer|systems?|holdings?|trading|group|company)\b\.?/gi

export function makerOf(vendor: string | null | undefined, randomised = false): string {
  if (randomised) return 'Hidden'
  if (!vendor) return 'Unknown maker'
  for (const [re, brand] of BRANDS) if (re.test(vendor)) return brand
  const short = vendor.replace(/\(.*?\)/g, '').replace(/[,&]/g, ' ').replace(NOISE, '').replace(/\s+/g, ' ').trim()
  const words = (short || vendor).split(' ').slice(0, 2).join(' ')
  // SHOUTED NAMES -> Title Case
  return words === words.toUpperCase() ? words.toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase()) : words
}
