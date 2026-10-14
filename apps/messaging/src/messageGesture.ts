/** Horizontal intent must dominate vertical movement so normal scrolling never replies. */
export function replyDistance(dx: number, dy: number): number {
  return dx > 10 && dx > Math.abs(dy) * 1.6 ? Math.min(dx, 80) : 0;
}
export function completesReply(dx: number, dy: number): boolean {
  return replyDistance(dx, dy) >= 56;
}
