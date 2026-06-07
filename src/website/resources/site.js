(function () {
  function byId(id) {
    return document.getElementById(id);
  }

  function setText(id, value) {
    const element = byId(id);
    if (element) {
      element.textContent = value == null ? "" : String(value);
    }
  }

  function setValue(id, value) {
    const element = byId(id);
    if (element) {
      element.value = value == null ? "" : String(value);
    }
  }

  function setField(id, value, state) {
    const element = byId(id);
    if (element) {
      element.textContent = value == null ? "" : String(value);
      if (state) {
        element.dataset.fieldState = state;
      } else {
        delete element.dataset.fieldState;
      }
    }
  }

  function clearField(id) {
    const element = byId(id);
    if (element) {
      element.textContent = "";
      delete element.dataset.fieldState;
    }
  }

  function setState(id, state) {
    const element = byId(id);
    if (element) {
      element.dataset.state = state || "";
    }
  }

  function setRuntimeStatus(state, text) {
    const element = byId("runtime-status");
    if (element) {
      element.dataset.state = state;
      element.textContent = text;
    }
  }

  function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        function () {
          setRuntimeStatus("ready", "Copied");
        },
        function () {
          setRuntimeStatus("ready", "Clipboard blocked");
        }
      );
    } else {
      setRuntimeStatus("ready", "Clipboard unavailable");
    }
  }

  async function loadTeaVM() {
    try {
      if (!window.TeaVM || !window.TeaVM.wasmGC) {
        throw new Error("TeaVM WasmGC runtime is not available.");
      }

      const teavm = await window.TeaVM.wasmGC.load("wasm-gc/uuid-tools-demo.wasm", {
        installImports() {
        }
      });
      teavm.exports.main([]);
      setRuntimeStatus("ready", "Wasm GC ready");
    } catch (error) {
      setRuntimeStatus("error", "Runtime failed");
      setText("generate-error", error && error.stack ? error.stack : String(error));
      setState("generator-panel", "error");
    }
  }

  window.UUIDToolsDemo = {
    setText,
    setValue,
    setField,
    clearField,
    setState,
    copyToClipboard
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", loadTeaVM);
  } else {
    loadTeaVM();
  }
})();
