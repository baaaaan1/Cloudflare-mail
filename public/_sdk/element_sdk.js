// Minimal stub for element SDK to avoid 404/errors in local use
// Provides .init that immediately calls onConfigChange with defaultConfig
(function(){
  const sdk = {
    init(opts){
      try {
        if (opts && typeof opts.onConfigChange === 'function') {
          opts.onConfigChange(opts.defaultConfig || {});
        }
      } catch(e) { console.warn('element_sdk onConfigChange error', e); }
    }
  };
  window.elementSdk = sdk;
})();
