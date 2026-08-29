export const githubLoginPattern = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
export const previewAccessOrigin = "https://preview-access.struktly.app";
const repositoryPattern = /^([A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?)\/([A-Za-z0-9._-]{1,100})$/;

export function hasPreviewAccessOrigin(request: Request): boolean {
  return request.headers.get("origin") === previewAccessOrigin;
}

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => {
    const escaped: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return escaped[character];
  });
}

export function parseRepository(value: string): { owner: string; repo: string } {
  const match = repositoryPattern.exec(value);
  if (!match) throw new Error("Invalid release repository configuration");
  return { owner: match[1], repo: match[2] };
}
