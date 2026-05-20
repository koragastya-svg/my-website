<?php
class AgastyaTablesApi {
    private PDO $pdo;
    private array $allowedTables = [
        'users','seminars','applications','news','inquiries','site_content',
        'leaf_readings','reading_slots','settings','logs','password_resets'
    ];

    private array $publicReadTables = ['seminars','news','site_content'];
    private array $selfReadableTables = ['applications','leaf_readings','inquiries'];

    public function __construct() {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_name('AGASTYA_SESS');
            session_set_cookie_params([
                'lifetime' => 0,
                'path' => '/',
                'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
            session_start();
        }

        $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=' . DB_CHARSET;
        $this->pdo = new PDO($dsn, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    }

    public function handle(): void {
        header('Content-Type: application/json; charset=utf-8');

        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        if ($method === 'OPTIONS') {
            http_response_code(204);
            return;
        }

        $route = $_GET['_route'] ?? '';
        $route = trim($route, '/');
        $parts = $route === '' ? [] : explode('/', $route);
        $table = $parts[0] ?? ($_GET['table'] ?? '');
        $id = $parts[1] ?? ($_GET['id'] ?? null);

        if ($table === 'auth') {
            $this->handleAuth($parts[1] ?? '');
            return;
        }

        $this->assertTable($table);
        $this->ensureBaseTable($table);

        switch ($method) {
            case 'GET':
                $this->authorizeRead($table, $id);
                if ($id) $this->getOne($table, $id);
                else $this->getList($table);
                break;
            case 'POST':
                if ($id) {
                    $this->authorizeWrite($table, $id, true);
                    $this->update($table, $id, true);
                } else {
                    $this->authorizeCreate($table);
                    $this->create($table);
                }
                break;
            case 'PUT':
            case 'PATCH':
                if (!$id) $this->badRequest('Missing id');
                $this->authorizeWrite($table, $id, false);
                $this->update($table, $id, false);
                break;
            case 'DELETE':
                if (!$id) $this->badRequest('Missing id');
                $this->authorizeDelete($table, $id);
                $this->delete($table, $id);
                break;
            default:
                http_response_code(405);
                echo json_encode(['success'=>false,'message'=>'Method not allowed'], JSON_UNESCAPED_UNICODE);
        }
    }

    /* =========================
       Auth endpoints
       /tables/auth/login
       /tables/auth/register
       /tables/auth/me
       /tables/auth/logout
       /tables/auth/save-reset-code
       /tables/auth/verify-reset-code
       /tables/auth/change-password
    ========================= */
    private function handleAuth(string $action): void {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

        if ($action === 'me' && $method === 'GET') {
            $user = $this->currentUser();
            if (!$user) $this->unauthorized('Not logged in');
            echo json_encode(['success'=>true,'user'=>$this->sanitizeUser($user, true)], JSON_UNESCAPED_UNICODE);
            return;
        }

        if ($action === 'logout') {
            $_SESSION = [];
            if (session_status() === PHP_SESSION_ACTIVE) session_destroy();
            echo json_encode(['success'=>true], JSON_UNESCAPED_UNICODE);
            return;
        }

        if ($method !== 'POST') {
            http_response_code(405);
            echo json_encode(['success'=>false,'message'=>'Method not allowed'], JSON_UNESCAPED_UNICODE);
            return;
        }

        $data = $this->input();

        if ($action === 'login') {
            $username = trim((string)($data['username'] ?? ''));
            $password = (string)($data['password'] ?? '');
            if ($username === '' || $password === '') $this->badRequest('Missing username or password');

            $stmt = $this->pdo->prepare("SELECT * FROM `users` WHERE `username` = ? AND (`deleted` = 0 OR `deleted` IS NULL) ORDER BY CASE WHEN `role` = 'admin' THEN 0 ELSE 1 END, `created_at` ASC LIMIT 1");
            $stmt->execute([$username]);
            $user = $stmt->fetch();

            if (!$user || ((string)($user['is_active'] ?? '1') === '0') || !$this->verifyPassword($password, (string)($user['password_hash'] ?? ''))) {
                http_response_code(401);
                echo json_encode(['success'=>false,'message'=>'아이디 또는 비밀번호가 올바르지 않습니다.'], JSON_UNESCAPED_UNICODE);
                return;
            }

            if (($user['role'] ?? '') === 'superadmin') {
                $user['role'] = 'admin';
                try {
                    $up = $this->pdo->prepare("UPDATE `users` SET `role` = 'admin', `updated_at` = ? WHERE `id` = ?");
                    $up->execute([(int)round(microtime(true) * 1000), $user['id']]);
                } catch (Throwable $e) {}
            }

            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'] ?? '';
            $_SESSION['role'] = $user['role'] ?? 'user';

            echo json_encode(['success'=>true,'user'=>$this->sanitizeUser($user, true)], JSON_UNESCAPED_UNICODE);
            return;
        }

        if ($action === 'register') {
            $username = trim((string)($data['username'] ?? ''));
            $password = (string)($data['password'] ?? '');
            $name = trim((string)($data['name'] ?? ''));
            $email = trim((string)($data['email'] ?? ''));
            $phone = trim((string)($data['phone'] ?? ''));
            $gender = trim((string)($data['gender'] ?? ''));

            if ($username === '' || $password === '' || $name === '' || $email === '') {
                $this->badRequest('Missing required fields');
            }
            if (!preg_match('/^[a-z0-9]{4,20}$/', $username)) {
                $this->badRequest('Invalid username');
            }

            $stmt = $this->pdo->prepare("SELECT `id` FROM `users` WHERE `username` = ? LIMIT 1");
            $stmt->execute([$username]);
            if ($stmt->fetch()) {
                echo json_encode(['success'=>false,'message'=>'이미 사용 중인 아이디입니다.'], JSON_UNESCAPED_UNICODE);
                return;
            }

            $stmt = $this->pdo->prepare("SELECT `id` FROM `users` WHERE `email` = ? LIMIT 1");
            $stmt->execute([$email]);
            if ($stmt->fetch()) {
                echo json_encode(['success'=>false,'message'=>'이미 가입된 이메일입니다.'], JSON_UNESCAPED_UNICODE);
                return;
            }

            $hash = $this->hashPassword($password);
            $now = (int)round(microtime(true) * 1000);
            $id = $this->uuid();

            $data = [
                'id' => $id,
                'username' => $username,
                'password_hash' => $hash,
                'name' => $name,
                'email' => $email,
                'phone' => $phone,
                'gender' => $gender,
                'role' => 'user',
                'reset_code' => '',
                'reset_code_expires' => '',
                'is_active' => 1,
                'created_at' => $now,
                'updated_at' => $now,
                'deleted' => 0,
            ];
            $this->ensureColumns('users', $data);

            $cols = array_keys($data);
            $sql = "INSERT INTO `users` (`" . implode('`,`', $cols) . "`) VALUES (" . implode(',', array_fill(0, count($cols), '?')) . ")";
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute(array_values($data));

            echo json_encode(['success'=>true,'user'=>$this->sanitizeUser($data, true)], JSON_UNESCAPED_UNICODE);
            return;
        }

        if ($action === 'save-reset-code') {
            $email = trim((string)($data['email'] ?? ''));
            $code = trim((string)($data['code'] ?? ''));
            if ($email === '' || $code === '') $this->badRequest('Missing email or code');

            $stmt = $this->pdo->prepare("SELECT `id`,`name`,`is_active` FROM `users` WHERE `email` = ? AND (`deleted` = 0 OR `deleted` IS NULL) LIMIT 1");
            $stmt->execute([$email]);
            $user = $stmt->fetch();
            if (!$user || ((string)($user['is_active'] ?? '1') === '0')) {
                echo json_encode(['success'=>false,'message'=>'등록되지 않은 이메일입니다.'], JSON_UNESCAPED_UNICODE);
                return;
            }

            $expires = (string)((int)round(microtime(true) * 1000) + 10 * 60 * 1000);
            $up = $this->pdo->prepare("UPDATE `users` SET `reset_code` = ?, `reset_code_expires` = ?, `updated_at` = ? WHERE `id` = ?");
            $up->execute([$code, $expires, (int)round(microtime(true) * 1000), $user['id']]);
            echo json_encode(['success'=>true,'userId'=>$user['id'],'name'=>$user['name'] ?? ''], JSON_UNESCAPED_UNICODE);
            return;
        }

        if ($action === 'verify-reset-code') {
            $email = trim((string)($data['email'] ?? ''));
            $code = trim((string)($data['code'] ?? ''));
            if ($email === '' || $code === '') $this->badRequest('Missing email or code');

            $stmt = $this->pdo->prepare("SELECT `id`,`reset_code`,`reset_code_expires` FROM `users` WHERE `email` = ? LIMIT 1");
            $stmt->execute([$email]);
            $user = $stmt->fetch();
            if (!$user) {
                echo json_encode(['success'=>false,'message'=>'사용자를 찾을 수 없습니다.'], JSON_UNESCAPED_UNICODE);
                return;
            }
            if ((string)($user['reset_code'] ?? '') !== $code) {
                echo json_encode(['success'=>false,'message'=>'인증 코드가 올바르지 않습니다.'], JSON_UNESCAPED_UNICODE);
                return;
            }
            if ((int)round(microtime(true) * 1000) > (int)($user['reset_code_expires'] ?? 0)) {
                echo json_encode(['success'=>false,'message'=>'인증 코드가 만료되었습니다.'], JSON_UNESCAPED_UNICODE);
                return;
            }

            $_SESSION['reset_user_id'] = $user['id'];
            echo json_encode(['success'=>true,'userId'=>$user['id']], JSON_UNESCAPED_UNICODE);
            return;
        }

        if ($action === 'change-password') {
            $userId = (string)($data['userId'] ?? '');
            $newPassword = (string)($data['newPassword'] ?? '');
            if ($userId === '' || $newPassword === '') $this->badRequest('Missing userId or password');

            $canChange = false;
            $user = $this->currentUser();
            if ($user && (($user['id'] ?? '') === $userId || $this->isAdmin())) $canChange = true;
            if (isset($_SESSION['reset_user_id']) && $_SESSION['reset_user_id'] === $userId) $canChange = true;

            if (!$canChange) $this->forbidden('Not allowed');

            $hash = $this->hashPassword($newPassword);
            $stmt = $this->pdo->prepare("UPDATE `users` SET `password_hash` = ?, `reset_code` = '', `reset_code_expires` = '', `updated_at` = ? WHERE `id` = ?");
            $stmt->execute([$hash, (int)round(microtime(true) * 1000), $userId]);
            unset($_SESSION['reset_user_id']);

            echo json_encode(['success'=>true], JSON_UNESCAPED_UNICODE);
            return;
        }

        $this->badRequest('Invalid auth action');
    }

    private function verifyPassword(string $password, string $storedHash): bool {
        if ($storedHash === '') return false;
        if (str_starts_with($storedHash, 'pbkdf2:')) {
            $parts = explode(':', $storedHash);
            if (count($parts) !== 3) return false;
            $salt = $parts[1];
            $expected = $parts[2];
            $hash = hash_pbkdf2('sha256', $password, $salt, 100000, 64, false);
            return hash_equals($expected, $hash);
        }
        return hash_equals($storedHash, hash('sha256', $password));
    }

    private function hashPassword(string $password): string {
        $salt = bin2hex(random_bytes(16));
        $hash = hash_pbkdf2('sha256', $password, $salt, 100000, 64, false);
        return 'pbkdf2:' . $salt . ':' . $hash;
    }

    private function currentUser(): ?array {
        $userId = $_SESSION['user_id'] ?? null;
        if (!$userId) return null;
        $stmt = $this->pdo->prepare("SELECT * FROM `users` WHERE `id` = ? AND (`deleted` = 0 OR `deleted` IS NULL) LIMIT 1");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();
        return $user ?: null;
    }

    private function currentUserId(): ?string {
        return $_SESSION['user_id'] ?? null;
    }

    private function isAdmin(): bool {
        $role = $_SESSION['role'] ?? '';
        return in_array($role, ['admin','superadmin'], true);
    }

    private function unauthorized(string $message = 'Unauthorized'): void {
        http_response_code(401);
        echo json_encode(['success'=>false,'message'=>$message], JSON_UNESCAPED_UNICODE);
        exit;
    }

    private function forbidden(string $message = 'Forbidden'): void {
        http_response_code(403);
        echo json_encode(['success'=>false,'message'=>$message], JSON_UNESCAPED_UNICODE);
        exit;
    }

    private function authorizeRead(string $table, ?string $id): void {
        if (in_array($table, $this->publicReadTables, true)) return;

        $uid = $this->currentUserId();

        if ($table === 'users') {
            if (!$uid) $this->unauthorized('Login required');
            if ($this->isAdmin()) return;
            if ($id && $id === $uid) return;
            $this->forbidden('Users list is restricted');
        }

        if (in_array($table, ['applications','leaf_readings','inquiries','reading_slots'], true)) {
            if (!$uid) $this->unauthorized('Login required');
            return;
        }

        if (!$this->isAdmin()) $this->forbidden('Admin only');
    }

    private function authorizeCreate(string $table): void {
        if ($table === 'users') return; // public registration compatibility
        if (in_array($table, ['applications','inquiries'], true)) return; // public forms
        if ($table === 'leaf_readings') {
            if (!$this->currentUserId()) $this->unauthorized('Login required');
            return;
        }
        if (!$this->isAdmin()) $this->forbidden('Admin only');
    }

    private function authorizeWrite(string $table, string $id, bool $allowPostUpsert): void {
        if ($this->isAdmin()) return;

        $uid = $this->currentUserId();
        if (!$uid) $this->unauthorized('Login required');

        if ($table === 'users') {
            if ($id !== $uid) $this->forbidden('Not your user record');
            return;
        }

        if (in_array($table, ['applications','leaf_readings'], true)) {
            if (!$this->ownsRow($table, $id, $uid)) $this->forbidden('Not your record');
            return;
        }

        if ($table === 'reading_slots') {
            // 로그인 사용자의 슬롯 잠금/예약 흐름에 필요. 실제 배정 로직은 클라이언트가 처리한다.
            return;
        }

        $this->forbidden('Admin only');
    }

    private function authorizeDelete(string $table, string $id): void {
        if ($this->isAdmin()) return;

        $uid = $this->currentUserId();
        if (!$uid) $this->unauthorized('Login required');

        if (in_array($table, ['applications','leaf_readings'], true) && $this->ownsRow($table, $id, $uid)) return;

        $this->forbidden('Admin only');
    }

    private function ownsRow(string $table, string $id, string $userId): bool {
        if (!in_array('user_id', $this->columns($table), true)) return false;
        $stmt = $this->pdo->prepare("SELECT `id` FROM `{$table}` WHERE `id` = ? AND `user_id` = ? LIMIT 1");
        $stmt->execute([$id, $userId]);
        return (bool)$stmt->fetch();
    }

    private function assertTable(string $table): void {
        if (!$table || !preg_match('/^[a-zA-Z0-9_]+$/', $table) || !in_array($table, $this->allowedTables, true)) {
            $this->badRequest('Invalid table');
        }
    }

    private function assertColumn(string $col): void {
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $col)) $this->badRequest('Invalid column');
    }

    private function ensureBaseTable(string $table): void {
        $sql = "CREATE TABLE IF NOT EXISTS `{$table}` (
            `id` VARCHAR(64) NOT NULL PRIMARY KEY,
            `created_at` BIGINT NULL,
            `updated_at` BIGINT NULL,
            `deleted` TINYINT(1) NOT NULL DEFAULT 0,
            INDEX (`created_at`),
            INDEX (`updated_at`),
            INDEX (`deleted`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
        $this->pdo->exec($sql);
    }

    private function columns(string $table): array {
        $stmt = $this->pdo->query("SHOW COLUMNS FROM `{$table}`");
        return array_column($stmt->fetchAll(), 'Field');
    }

    private function ensureColumns(string $table, array $data): void {
        if (!defined('AUTO_ADD_COLUMNS') || !AUTO_ADD_COLUMNS) return;
        $existing = $this->columns($table);
        foreach ($data as $col => $_) {
            $this->assertColumn($col);
            if (in_array($col, $existing, true)) continue;
            if ($col === 'id') continue;
            $type = in_array($col, ['created_at','updated_at','original_created_at','leader_upgraded_at','reset_code_expires'], true)
                ? 'BIGINT NULL'
                : 'LONGTEXT NULL';
            $this->pdo->exec("ALTER TABLE `{$table}` ADD COLUMN `{$col}` {$type}");
            $existing[] = $col;
        }
    }

    private function input(): array {
        $raw = file_get_contents('php://input');
        if ($raw === false || trim($raw) === '') return [];
        $data = json_decode($raw, true);
        if (!is_array($data)) $this->badRequest('Invalid JSON');
        return $data;
    }

    private function normalizeValue($v) {
        if (is_bool($v)) return $v ? '1' : '0';
        if (is_array($v) || is_object($v)) return json_encode($v, JSON_UNESCAPED_UNICODE);
        return $v;
    }

    private function normalizeRow(array $row): array {
        foreach ($row as $k => $v) {
            if ($v === null) continue;
            if (in_array($k, ['deleted'], true)) $row[$k] = (bool)$v;
            if (is_string($v)) {
                $t = trim($v);
                if (($t !== '') && (($t[0] === '[' && substr($t,-1) === ']') || ($t[0] === '{' && substr($t,-1) === '}'))) {
                    $decoded = json_decode($t, true);
                    if (json_last_error() === JSON_ERROR_NONE) $row[$k] = $decoded;
                }
            }
        }
        return $row;
    }

    private function sanitizeRow(string $table, array $row): array {
        $row = $this->normalizeRow($row);

        if ($table === 'users') {
            $includeFingerprint = $this->isAdmin() || (($row['id'] ?? null) === $this->currentUserId());
            return $this->sanitizeUser($row, $includeFingerprint);
        }

        return $row;
    }

    private function sanitizeUser(array $row, bool $includeFingerprint = false): array {
        unset($row['password_hash'], $row['reset_code'], $row['reset_code_expires']);
        if (!$includeFingerprint) unset($row['fingerprint_data']);
        return $this->normalizeRow($row);
    }

    private function getList(string $table): void {
        $limit = max(1, min(1000, intval($_GET['limit'] ?? 500)));
        $page = max(1, intval($_GET['page'] ?? 1));
        $offset = ($page - 1) * $limit;
        $search = trim($_GET['search'] ?? '');

        $where = [];
        $params = [];

        // 회원은 본인 데이터만, 관리자는 전체 데이터.
        if (!$this->isAdmin()) {
            $uid = $this->currentUserId();
            if (in_array($table, ['applications','leaf_readings','inquiries'], true)) {
                $where[] = "`user_id` = ?";
                $params[] = $uid;
            }
        }

        if ($search !== '') {
            $cols = array_filter($this->columns($table), fn($c) => !in_array($c, ['deleted'], true));
            // users 검색에서는 민감 컬럼 검색 제외
            if ($table === 'users') {
                $cols = array_filter($cols, fn($c) => !in_array($c, ['password_hash','reset_code','reset_code_expires','fingerprint_data'], true));
            }
            $likes = [];
            foreach ($cols as $c) {
                $likes[] = "CAST(`{$c}` AS CHAR) LIKE ?";
                $params[] = '%' . $search . '%';
            }
            if ($likes) $where[] = '(' . implode(' OR ', $likes) . ')';
        }
        $whereSql = $where ? (' WHERE ' . implode(' AND ', $where)) : '';
        $sql = "SELECT * FROM `{$table}`{$whereSql} LIMIT {$limit} OFFSET {$offset}";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        $rows = array_map(fn($r) => $this->sanitizeRow($table, $r), $stmt->fetchAll());
        echo json_encode(['data'=>$rows, 'rows'=>$rows, 'page'=>$page, 'limit'=>$limit], JSON_UNESCAPED_UNICODE);
    }

    private function getOne(string $table, string $id): void {
        $stmt = $this->pdo->prepare("SELECT * FROM `{$table}` WHERE `id` = ? LIMIT 1");
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        if (!$row) {
            http_response_code(404);
            echo json_encode(['success'=>false,'message'=>'Not found'], JSON_UNESCAPED_UNICODE);
            return;
        }
        echo json_encode(['data'=>$this->sanitizeRow($table, $row)], JSON_UNESCAPED_UNICODE);
    }

    private function create(string $table): void {
        $data = $this->input();

        // 클라이언트가 민감한 역할/관리자 필드를 임의 지정하지 못하게 보정.
        if ($table === 'users') {
            $username = trim((string)($data['username'] ?? ''));
            $email = trim((string)($data['email'] ?? ''));

            // 관리자 계정은 신청/자동생성 흐름에서 절대 새로 만들지 않음
            if ($username === 'admin' || strtolower($email) === 'kor.agastya@gmail.com') {
                http_response_code(403);
                echo json_encode(['success'=>false, 'message'=>'관리자 계정은 자동 생성할 수 없습니다.'], JSON_UNESCAPED_UNICODE);
                return;
            }

            // 같은 아이디 또는 이메일의 활성 회원이 있으면 새 회원 생성 금지
            if ($username !== '' || $email !== '') {
                $dupSql = "SELECT `id`, `username`, `email`, `role`, `deleted` FROM `users`
                           WHERE (`username` = ? OR `email` = ?)
                             AND (`deleted` = 0 OR `deleted` IS NULL)
                           LIMIT 1";
                $dupStmt = $this->pdo->prepare($dupSql);
                $dupStmt->execute([
                    $username !== '' ? $username : '__NO_USERNAME__',
                    $email !== '' ? $email : '__NO_EMAIL__'
                ]);
                $existingUser = $dupStmt->fetch();

                if ($existingUser) {
                    http_response_code(409);
                    echo json_encode([
                        'success' => false,
                        'message' => '이미 같은 아이디 또는 이메일의 회원이 존재합니다.',
                        'existing_user_id' => $existingUser['id'] ?? null
                    ], JSON_UNESCAPED_UNICODE);
                    return;
                }
            }

            $data['role'] = 'user';
            $data['is_active'] = $data['is_active'] ?? true;
            unset($data['reset_code'], $data['reset_code_expires']);
        }
        if ($table === 'leaf_readings' && $this->currentUserId() && !$this->isAdmin()) {
            $data['user_id'] = $this->currentUserId();
        }

        if (!isset($data['id']) || !$data['id']) $data['id'] = $this->uuid();
        $now = (int)round(microtime(true) * 1000);
        if (!isset($data['created_at'])) $data['created_at'] = $now;
        $data['updated_at'] = $now;
        $this->ensureColumns($table, $data);
        $cols = array_keys($data);
        foreach ($cols as $c) $this->assertColumn($c);
        $placeholders = implode(',', array_fill(0, count($cols), '?'));
        $colSql = '`' . implode('`,`', $cols) . '`';
        $values = array_map(fn($c) => $this->normalizeValue($data[$c]), $cols);
        $sql = "INSERT INTO `{$table}` ({$colSql}) VALUES ({$placeholders})";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($values);
        $this->getOne($table, (string)$data['id']);
    }

    private function update(string $table, string $id, bool $allowPostUpsert): void {
        $data = $this->input();
        unset($data['id']);

        if (!$this->isAdmin()) {
            if ($table === 'users') {
                // 일반 회원은 프로필/지문 관련 필드만 직접 수정 가능.
                $allowed = ['name','phone','birthdate','gender','fingerprint_data'];
                $data = array_intersect_key($data, array_flip($allowed));
            } elseif (in_array($table, ['applications','leaf_readings'], true)) {
                // 일반 회원이 소유권/관리자 필드를 바꾸지 못하게 최소 제한.
                unset($data['user_id'], $data['role'], $data['deleted']);
            }
        }

        $data['updated_at'] = (int)round(microtime(true) * 1000);
        $this->ensureColumns($table, $data);
        $sets = [];
        $values = [];
        foreach ($data as $col => $val) {
            $this->assertColumn($col);
            $sets[] = "`{$col}` = ?";
            $values[] = $this->normalizeValue($val);
        }
        if (!$sets) $this->badRequest('No data');
        $values[] = $id;
        $stmt = $this->pdo->prepare("UPDATE `{$table}` SET " . implode(',', $sets) . " WHERE `id` = ?");
        $stmt->execute($values);
        if ($stmt->rowCount() === 0 && $allowPostUpsert) {
            $data['id'] = $id;
            $this->create($table);
            return;
        }
        $this->getOne($table, $id);
    }

    private function delete(string $table, string $id): void {
        $stmt = $this->pdo->prepare("DELETE FROM `{$table}` WHERE `id` = ?");
        $stmt->execute([$id]);
        echo json_encode(['success'=>true], JSON_UNESCAPED_UNICODE);
    }

    private function uuid(): string {
        return bin2hex(random_bytes(16));
    }

    private function badRequest(string $message): void {
        http_response_code(400);
        echo json_encode(['success'=>false,'message'=>$message], JSON_UNESCAPED_UNICODE);
        exit;
    }
}
?>
