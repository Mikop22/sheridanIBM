const monthNames = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

/** Product-supported replay range. This is configuration, not prediction data. */
export const supportedReplayMonths = Array.from({ length: 24 }, (_, index) => {
  const year = 2024 + Math.floor(index / 12);
  const monthIndex = index % 12;
  return {
    value: `${year}-${String(monthIndex + 1).padStart(2, "0")}`,
    label: `${monthNames[monthIndex]} ${year}`,
    shortLabel: monthNames[monthIndex].slice(0, 3),
  };
});
