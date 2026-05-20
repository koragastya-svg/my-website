<?php
/**
 * 지문 이미지 업로드 엔드포인트
 * - multipart/form-data 의 "fingerprint" 파일을 받아 원본 그대로 저장한다.
 * - 저장 위치: /uploads/fingerprints/ (api 폴더 기준 ../uploads/fingerprints)
 * - DB(leaf_readings.fingerprint_image)에는 base64가 아니라 이 URL만 저장한다.
 *
 * 폴더 준비 안내:
 *   서버에 uploads/fingerprints/ 폴더가 없으면 자동 생성한다(0775).
 *   자동 생성이 실패하는 환경(권한 문제)이라면 수동으로 다음 폴더를 만들고
 *   웹서버 쓰기 권한을 부여해야 한다:
 *     - 운영:   /uploads/fingerprints/
 *     - 테스트: /www-test/uploads/fingerprints/
 *
 * 성공 응답: { "success": true, "url": "/uploads/fingerprints/파일명.png" }
 * 실패 응답: { "success": false, "message": "..." }
 */

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

function fail($msg, $code = 400) {
    http_response_code($code);
    echo json_encode(['success' => false, 'message' => $msg], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    fail('POST 요청만 허용됩니다.', 405);
}

if (!isset($_FILES['fingerprint'])) {
    fail('업로드된 지문 파일이 없습니다. (필드명: fingerprint)');
}

$file = $_FILES['fingerprint'];

if (!empty($file['error']) && $file['error'] !== UPLOAD_ERR_OK) {
    $errMap = [
        UPLOAD_ERR_INI_SIZE   => '서버 설정상 허용된 파일 크기를 초과했습니다.',
        UPLOAD_ERR_FORM_SIZE  => '폼 설정상 허용된 파일 크기를 초과했습니다.',
        UPLOAD_ERR_PARTIAL    => '파일이 일부만 업로드되었습니다. 다시 시도해주세요.',
        UPLOAD_ERR_NO_FILE    => '업로드된 파일이 없습니다.',
        UPLOAD_ERR_NO_TMP_DIR => '서버 임시 폴더가 없습니다.',
        UPLOAD_ERR_CANT_WRITE => '서버에 파일을 쓸 수 없습니다.',
    ];
    fail($errMap[$file['error']] ?? ('업로드 오류 코드: ' . $file['error']));
}

// 최대 8MB 제한
$MAX_BYTES = 8 * 1024 * 1024;
if ($file['size'] <= 0) {
    fail('빈 파일은 업로드할 수 없습니다.');
}
if ($file['size'] > $MAX_BYTES) {
    fail('파일 크기가 너무 큽니다. 최대 8MB까지 업로드할 수 있습니다.');
}

// 허용 확장자 / MIME
$ALLOWED_EXT  = ['jpg', 'jpeg', 'png', 'webp'];
$ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/webp'];

$origName = $file['name'] ?? '';
$ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
if (!in_array($ext, $ALLOWED_EXT, true)) {
    fail('허용되지 않는 확장자입니다. (jpg, jpeg, png, webp 만 가능)');
}

// 실제 MIME 검사 (가능한 경우)
$mime = '';
if (function_exists('finfo_open')) {
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    if ($finfo) {
        $mime = finfo_file($finfo, $file['tmp_name']) ?: '';
        finfo_close($finfo);
    }
}
if ($mime && !in_array($mime, $ALLOWED_MIME, true)) {
    fail('이미지 파일이 아니거나 허용되지 않는 형식입니다.');
}

// 저장 폴더 준비 (api 폴더 기준 상위의 uploads/fingerprints)
$baseDir = realpath(__DIR__ . '/..');
if ($baseDir === false) {
    fail('서버 경로를 확인할 수 없습니다.', 500);
}
$uploadDir = $baseDir . '/uploads/fingerprints';
if (!is_dir($uploadDir)) {
    if (!@mkdir($uploadDir, 0775, true) && !is_dir($uploadDir)) {
        fail('업로드 폴더를 생성할 수 없습니다. uploads/fingerprints 폴더 권한을 확인해주세요.', 500);
    }
}
if (!is_writable($uploadDir)) {
    fail('업로드 폴더에 쓰기 권한이 없습니다. uploads/fingerprints 권한을 확인해주세요.', 500);
}

// 안전한 파일명 생성: 원본 화질 그대로 보존 (압축/리사이즈 없음)
try {
    $rand = bin2hex(random_bytes(8));
} catch (Exception $e) {
    $rand = substr(md5(uniqid('', true)), 0, 16);
}
$filename = 'fp_' . date('Ymd_His') . '_' . $rand . '.' . $ext;
$target   = $uploadDir . '/' . $filename;

if (!move_uploaded_file($file['tmp_name'], $target)) {
    fail('파일 저장에 실패했습니다. 다시 시도해주세요.', 500);
}

$url = '/uploads/fingerprints/' . $filename;
echo json_encode(['success' => true, 'url' => $url], JSON_UNESCAPED_UNICODE);
