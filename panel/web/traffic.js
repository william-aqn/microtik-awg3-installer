'use strict';
function trafficBytes(value) {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let size = Number(value), unit = 0;
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit++; }
  return new Intl.NumberFormat(undefined, {maximumFractionDigits: unit ? 1 : 0}).format(size)+' '+units[unit];
}
function renderTraffic(data) {
  const section = document.getElementById('traffic');
  const valid = data?.available && ['direct', 'vpn'].every(path =>
    ['upload', 'download'].every(direction => ['bytes', 'packets'].every(key =>
      Number.isFinite(data[path]?.[direction]?.[key]) && data[path][direction][key] >= 0)));
  section.classList.toggle('unavailable', !valid);
  for (const path of ['direct', 'vpn']) {
    const value = valid ? data[path] : null;
    document.getElementById('traffic-'+path+'-total').textContent = value ? trafficBytes(value.upload.bytes+value.download.bytes) : '\u2014';
    document.getElementById('traffic-'+path+'-download').textContent = value ? trafficBytes(value.download.bytes) : '\u2014';
    document.getElementById('traffic-'+path+'-upload').textContent = value ? trafficBytes(value.upload.bytes) : '\u2014';
    document.getElementById('traffic-'+path+'-packets').textContent = value ? new Intl.NumberFormat().format(value.upload.packets+value.download.packets)+' packets' : 'No current reading';
  }
  const updated = valid ? new Date(data.sampled_at) : null;
  document.getElementById('traffic-status').textContent = valid
    ? 'Updated '+(Number.isNaN(updated.getTime()) ? 'just now' : updated.toLocaleTimeString())+' / every 5 s'
    : data?.error || 'Traffic counters unavailable';
}
