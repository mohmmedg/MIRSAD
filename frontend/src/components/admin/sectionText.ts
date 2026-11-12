export function adminSectionText(language: string, arabic: string, english: string): string {
  return language === "ar" ? arabic : english;
}
