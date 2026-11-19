<?php
/* FastCGI keep-alive client for the CVE-2026-129289 check: a port of the
 * transact()/request() helpers in php-src's sapi/fpm/tests/unread-body-*.phpt.
 *
 * Usage: php7.4 -n keepconn.php <port> <script> <scenario>
 * Prints one line per transaction, e.g. "keep on: safe, served".
 */
function record($type, $content, $id)
{
    return pack('CCnnCC', 1, $type, $id, strlen($content), 0, 0) . $content;
}

function params(array $params)
{
    $encoded = '';
    foreach ($params as $name => $value) {
        foreach (array(strlen($name), strlen($value)) as $len) {
            $encoded .= $len < 128 ? chr($len) : pack('N', $len | 0x80000000);
        }
        $encoded .= $name . $value;
    }
    return $encoded;
}

function request($id, $keep, array $params, $stdin)
{
    return record(1, pack('nCxxxxx', 1, $keep ? 1 : 0), $id)
        . record(4, params($params), $id)
        . record(4, '', $id)
        . record(5, $stdin, $id)
        . record(5, '', $id);
}

function transact($port, $request)
{
    $socket = fsockopen('127.0.0.1', (int) $port, $errno, $errstr, 5);
    if (!$socket) {
        return '';
    }
    stream_set_timeout($socket, 3);
    $written = 0;
    while ($written < strlen($request)) {
        $n = fwrite($socket, substr($request, $written));
        if ($n === false || $n === 0) {
            break;
        }
        $written += $n;
    }
    stream_socket_shutdown($socket, STREAM_SHUT_WR);
    $response = stream_get_contents($socket);
    fclose($socket);
    return (string) $response;
}

function has($haystack, $needle)
{
    return strpos($haystack, $needle) !== false;
}

list(, $port, $script, $scenario) = $argv;
$base = array(
    'GATEWAY_INTERFACE' => 'FastCGI/1.0',
    'SCRIPT_FILENAME' => $script,
    'SERVER_PROTOCOL' => 'HTTP/1.1',
);
$hidden = request(2, false, $base + array(
    'REQUEST_METHOD' => 'GET',
    'SCRIPT_NAME' => '/smuggled.php',
    'REQUEST_URI' => '/smuggled.php',
    'REMOTE_ADDR' => '203.0.113.1',
    'CONTENT_LENGTH' => '0',
), '');
$outer = $base + array(
    'REQUEST_METHOD' => 'POST',
    'SCRIPT_NAME' => '/open.php',
    'REQUEST_URI' => '/open.php',
    'REMOTE_ADDR' => '127.0.0.1',
);

if ($scenario === 'unread-body') {
    /* A malformed multipart body stops the parser early; the script opens
     * php://input without reading it; the forged request sits in the rest. */
    $body = str_pad("--B\r\nContent-Disposition: form-data\r\n\r\n", 12000, 'A');
    $body = substr_replace($body, $hidden, 5120, strlen($hidden));
    $p = $outer + array('CONTENT_TYPE' => 'multipart/form-data; boundary=B',
        'CONTENT_LENGTH' => (string) strlen($body));
    foreach (array(false, true) as $keep) {
        $r = transact($port, request(1, $keep, $p, $body));
        echo 'keep ', $keep ? 'on' : 'off', ': ', has($r, 'smuggled') ? 'smuggled' : 'safe', "\n";
    }
    $p['CONTENT_TYPE'] = 'application/octet-stream';
    $p['CONTENT_LENGTH'] = '1';
    $r = transact($port, request(1, true, $p, 'A' . $hidden));
    echo 'partial frame: ', has($r, 'smuggled') ? 'smuggled' : 'safe', "\n";
} else {
    /* The STDIN record is longer than CONTENT_LENGTH, so it is left partly
     * read; the only worker must still serve the following connections. */
    $p = $outer + array('CONTENT_TYPE' => 'application/octet-stream', 'CONTENT_LENGTH' => '1');
    $plain = array('REQUEST_METHOD' => 'GET', 'CONTENT_LENGTH' => '0') + $p;
    unset($plain['CONTENT_TYPE']);
    foreach (array(false, true) as $keep) {
        $r = transact($port, request(1, $keep, $p, 'A' . $hidden));
        echo 'keep ', $keep ? 'on' : 'off', ': ', has($r, 'smuggled') ? 'smuggled' : 'safe', ', ',
            has($r, 'outer 1') ? 'served' : 'not served', "\n";
        foreach (array(1, 2) as $n) {
            $r = transact($port, request(1, false, $plain, ''));
            echo "  next connection $n: ", has($r, 'outer 0') ? 'served' : 'not served', "\n";
        }
    }
}
