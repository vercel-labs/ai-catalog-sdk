export const RFC3339_PATTERN_SOURCE =
  '^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(?:\\.([0-9]+))?(?:[Zz]|([+-])([01][0-9]|2[0-3]):([0-5][0-9]))$';

const rfc3339Pattern = new RegExp(RFC3339_PATTERN_SOURCE);

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

export function isRfc3339DateTime(value: string): boolean {
  const match = rfc3339Pattern.exec(value);
  if (!match) return false;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const daysInMonth = [
    31,
    isLeapYear(year) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];

  if (day > (daysInMonth[month - 1] ?? 0)) return false;
  if (second !== 60) return true;

  const offsetSign = match[8];
  const offsetHour = Number(match[9] ?? 0);
  const offsetMinute = Number(match[10] ?? 0);
  const offset =
    (offsetSign === '-' ? -1 : 1) * (offsetHour * 60 + offsetMinute);
  const utc = new Date(0);
  utc.setUTCFullYear(year, month - 1, day);
  utc.setUTCHours(hour, minute - offset, 0, 0);
  const utcMonth = utc.getUTCMonth();
  const lastDay = utcMonth === 5 ? 30 : 31;

  return (
    (utcMonth === 5 || utcMonth === 11) &&
    utc.getUTCDate() === lastDay &&
    utc.getUTCHours() === 23 &&
    utc.getUTCMinutes() === 59
  );
}

/** Compare valid RFC 3339 instants without truncating fractional seconds. */
export function compareRfc3339DateTimes(left: string, right: string): number {
  const parts = (
    value: string,
  ): { second: number; leap: boolean; fraction: string } => {
    if (!isRfc3339DateTime(value))
      throw new TypeError('Expected a valid RFC 3339 timestamp.');
    const match = rfc3339Pattern.exec(value);
    if (!match) throw new TypeError('Expected a valid RFC 3339 timestamp.');
    const offset =
      (match[8] === '-' ? -1 : 1) *
      (Number(match[9] ?? 0) * 60 + Number(match[10] ?? 0));
    const leap = match[6] === '60';
    const instant = new Date(0);
    instant.setUTCFullYear(
      Number(match[1]),
      Number(match[2]) - 1,
      Number(match[3]),
    );
    instant.setUTCHours(
      Number(match[4]),
      Number(match[5]) - offset,
      Math.min(Number(match[6]), 59),
      0,
    );
    return { second: instant.getTime() / 1000, leap, fraction: match[7] ?? '' };
  };
  const a = parts(left);
  const b = parts(right);
  if (a.second !== b.second) return a.second < b.second ? -1 : 1;
  if (a.leap !== b.leap) return a.leap ? 1 : -1;
  const width = Math.max(a.fraction.length, b.fraction.length);
  const af = a.fraction.padEnd(width, '0');
  const bf = b.fraction.padEnd(width, '0');
  return af === bf ? 0 : af < bf ? -1 : 1;
}
