document.addEventListener('DOMContentLoaded', () => {
  const dropArea   = document.getElementById('drop-area');
  const fileInput  = document.getElementById('file-input');
  const chooseBtn  = document.getElementById('choose-btn');
  const progressEl = document.getElementById('progress-list');

  chooseBtn.addEventListener('click', () => fileInput.click());
  dropArea.addEventListener('click', (e) => {
    if (e.target.closest('button, a')) return;
    fileInput.click();
  });

  ['dragenter','dragover'].forEach(evt =>
    dropArea.addEventListener(evt, e => { e.preventDefault(); e.stopPropagation(); dropArea.classList.add('highlight'); })
  );
  ['dragleave','drop'].forEach(evt =>
    dropArea.addEventListener(evt, e => { e.preventDefault(); e.stopPropagation(); dropArea.classList.remove('highlight'); })
  );
  dropArea.addEventListener('drop', e => startUpload(e.dataTransfer.files));
  fileInput.addEventListener('change', () => startUpload(fileInput.files));

  function startUpload(fileList) {
    if (!fileList || !fileList.length) return;
    progressEl.innerHTML = '';
    const files = Array.from(fileList);
    (async function loop() {
      for (const f of files) await uploadOne(f);
      fileInput.value = '';
    })();
  }

  function makeProgressItem(name) {
    const row = document.createElement('div');
    row.className = 'progress-item';
    row.innerHTML = `
      <div class="progress-name" title="${name}">${name}</div>
      <div class="progress-bar"><span class="bar"></span></div>
      <div class="progress-status">0%</div>
    `;
    progressEl.appendChild(row);
    return {
      bar: row.querySelector('.bar'),
      status: row.querySelector('.progress-status'),
      root: row
    };
  }

  function uploadOne(file) {
    return new Promise((resolve) => {
      const ui = makeProgressItem(file.name);
      const form = new FormData();
      form.append('file', file);

      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/upload', true);
      xhr.withCredentials = true;

      xhr.upload.onprogress = (e) => {
        if (!e.lengthComputable) return;
        const p = Math.round((e.loaded / e.total) * 100);
        ui.bar.style.width = p + '%';
        ui.status.textContent = p + '%';
      };

      xhr.onreadystatechange = () => {
        if (xhr.readyState !== 4) return;

        // Always have a payload object available
        let payload = {};
        try { payload = JSON.parse(xhr.responseText || '{}'); } catch (e) { payload = {}; }

        // We upload one file per request, so results[0] corresponds to this file
        const result = Array.isArray(payload.results) && payload.results[0] ? payload.results[0] : null;
        const serverStatus = result && result.status ? result.status : null;
        const serverMsg    = result && result.message ? result.message : null;

        if (xhr.status >= 200 && xhr.status < 300) {
          // Show actual server status instead of generic "Done"
          if (serverStatus === 'ok') {
            ui.bar.style.width = '100%';
            ui.status.textContent = 'Uploaded';
            ui.status.classList.add('ok');
          } else if (serverStatus) {
            ui.status.textContent = `Rejected (${serverStatus})`;
            ui.status.classList.add('err');
            if (serverMsg) ui.root.title = serverMsg;
          } else {
            // Fallback if server didn’t include results
            ui.bar.style.width = '100%';
            ui.status.textContent = 'Uploaded';
            ui.status.classList.add('ok');
          }
        } else {
          const msg = serverMsg || xhr.statusText || 'Upload failed';
          ui.status.textContent = 'Error';
          ui.status.classList.add('err');
          ui.root.title = msg;
        }
        resolve();
      };

      xhr.send(form);
    });
  }
});
