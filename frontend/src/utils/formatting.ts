/**
 * Formatting and Display Utilities.
 * Enforces tabular alignment and human-readable security formats.
 */

import { RiskClass } from '../types/core';

export function formatTimestamp(unixSeconds: number): string {
  if (!unixSeconds) return '—';
  const date = new Date(unixSeconds * 1000);
  return date.toISOString().replace('T', ' ').replace('Z', ' UTC');
}

export function formatTimeAgo(unixSeconds: number): string {
  if (!unixSeconds) return '—';
  const now = Math.floor(Date.now() / 1000);
  const diff = now - unixSeconds;
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function formatCountdown(expiresAtUnix: number): string {
  const now = Math.floor(Date.now() / 1000);
  const remaining = expiresAtUnix - now;
  if (remaining <= 0) return 'EXPIRED';
  const m = Math.floor(remaining / 60);
  const s = remaining % 60;
  return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
}

export function truncateHash(hash: string, startChars: number = 8, endChars: number = 6): string {
  if (!hash) return '—';
  const clean = hash.replace(/^sha256:/, '');
  if (clean.length <= startChars + endChars) return hash;
  return `${clean.substring(0, startChars)}...${clean.substring(clean.length - endChars)}`;
}

export function formatNumber(num: number): string {
  return new Intl.NumberFormat('en-US').format(num);
}

export function getRiskBadgeClass(risk: RiskClass): string {
  switch (risk) {
    case 'OBSERVATION':
      return 'badge-neutral';
    case 'LOW':
      return 'badge-neutral';
    case 'MODERATE':
      return 'badge-primary';
    case 'HIGH':
      return 'badge-warning';
    case 'CRITICAL':
      return 'badge-danger';
    default:
      return 'badge-neutral';
  }
}
