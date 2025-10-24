// api/register.js
const admin = require('firebase-admin');

// --- Cấu hình Firebase Admin SDK ---
// **QUAN TRỌNG:** Đảm bảo biến môi trường FIREBASE_SERVICE_ACCOUNT_KEY đã được setup trên Vercel
let serviceAccount;
try {
    // Cố gắng parse key từ biến môi trường
    if (process.env.FIREBASE_SERVICE_ACCOUNT_KEY) {
        serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
    } else {
        throw new Error("FIREBASE_SERVICE_ACCOUNT_KEY environment variable is not set.");
    }
} catch (e) {
    console.error('Failed to parse FIREBASE_SERVICE_ACCOUNT_KEY:', e);
    // Có thể throw lỗi ở đây để function fail luôn nếu key sai
    // Hoặc xử lý mặc định tùy theo yêu cầu bảo mật
}

// Khởi tạo Firebase Admin App (chỉ một lần)
try {
    if (!admin.apps.length && serviceAccount) { // Chỉ khởi tạo nếu serviceAccount hợp lệ
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
            // databaseURL: "YOUR_DATABASE_URL" // Thêm nếu cần
        });
        console.log("Firebase Admin SDK initialized successfully.");
    } else if (!serviceAccount) {
         console.error("Firebase Admin SDK NOT initialized - Service Account Key is missing or invalid.");
    }
} catch (e) {
    console.error('Firebase Admin Initialization Error:', e);
}
// Chỉ lấy db và auth nếu admin đã khởi tạo thành công
const db = admin.apps.length ? admin.firestore() : null;
const auth = admin.apps.length ? admin.auth() : null;
// ------------------------------------

// --- Hàm xử lý chính ---
module.exports = async (req, res) => {
    // --- CORS Headers ---
    // --- KHỐI CODE CORS QUAN TRỌNG ---
    // Cho phép request từ bất kỳ origin nào (tiện lợi khi dev)
    // **LƯU Ý:** Khi deploy thật, nên đổi '*' thành domain web của cậu (vd: https://your-qola-app.vercel.app)
    res.setHeader('Access-Control-Allow-Origin', '*');
    // Cho phép các phương thức cần thiết
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    // Cho phép các header cần thiết (vd: Content-Type)
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    // Xử lý request OPTIONS (trình duyệt gửi trước khi POST để kiểm tra CORS)
    if (req.method === 'OPTIONS') {
        return res.status(200).end(); // Trả về 200 OK ngay lập tức
    }
    // --- KẾT THÚC KHỐI CORS ---

    // Kiểm tra SDK đã khởi tạo chưa
    if (!db || !auth) {
        console.error("Firebase Admin SDK is not initialized.");
        return res.status(500).json({ error: 'Server configuration error.' });
    }

    // Chỉ cho phép POST
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    // Lấy IP
    const ipAddress = req.headers['x-forwarded-for']?.split(',').shift() || req.socket?.remoteAddress;
    if (!ipAddress) {
         console.warn("Could not determine IP address. Headers:", req.headers);
         // Vẫn tiếp tục nhưng không check IP limit, hoặc trả lỗi tùy ý
         // return res.status(400).json({ error: 'Could not determine IP address.' });
    }
    const normalizedIp = ipAddress ? (ipAddress.includes(':') ? ipAddress.split(':').slice(-1)[0] : ipAddress) : null;

    const { username, email, password } = req.body;
    const lowerCaseUsername = username?.toLowerCase(); // Thêm ?. để tránh lỗi nếu username là null/undefined

    // --- Kiểm tra Input ---
    if (!username || !email || !password || password.length < 6 || username.length < 3 || /\s/.test(username) || !/^[a-z0-9_.]+$/.test(username)) {
        return res.status(400).json({ error: 'Invalid registration data.' });
    }

    try {
        // --- BƯỚC 1: KIỂM TRA EMAIL TỒN TẠI (NGOÀI TRANSACTION) ---
        try {
            await auth.getUserByEmail(email);
            console.log(`Email already exists: ${email}`);
            return res.status(409).json({ error: 'Email already in use.' });
        } catch (error) {
            if (error.code !== 'auth/user-not-found') {
                console.error("Error checking email BEFORE transaction:", error);
                throw new Error('Error verifying email availability.');
            }
            console.log(`Email available: ${email}`);
        }

        // --- BƯỚC 2: CHẠY TRANSACTION ---
        let newUserRecordUid = null; // Chỉ lưu UID để trả về
        await db.runTransaction(async (transaction) => {
            // 2.1. Kiểm tra giới hạn IP (chỉ check nếu lấy được IP)
            if (normalizedIp) {
                 const ipRef = db.collection('ipRegistrationCounts').doc(normalizedIp);
                 const ipDoc = await transaction.get(ipRef);
                 const currentCount = ipDoc.exists ? ipDoc.data().count : 0;
                 if (currentCount >= 3) {
                     throw new Error('IP limit reached');
                 }
            } else {
                 console.warn("Skipping IP limit check as IP address is unavailable.");
            }


            // 2.2. Kiểm tra username tồn tại (trong Firestore)
            const usersRef = db.collection("users");
            const qUsername = usersRef.where("username", "==", lowerCaseUsername);
            const usernameSnapshot = await transaction.get(qUsername);
            if (!usernameSnapshot.empty) {
                throw new Error('Username already in use');
            }

            // --- Nếu IP (nếu có check) và Username OK ---
            // 2.3. Tạo User Auth (BẮT BUỘC NGOÀI TRANSACTION) - Tạo trước để lấy UID
            let tempUserRecord;
            try {
                 tempUserRecord = await auth.createUser({
                     email: email,
                     password: password,
                     displayName: username
                 });
                 newUserRecordUid = tempUserRecord.uid; // Lưu UID lại
                 console.log(`Auth user created: ${newUserRecordUid}`);
            } catch (authError) {
                 console.error("Firebase Auth createUser error:", authError);
                 if (authError.code === 'auth/email-already-exists') throw new Error('Email already in use');
                 if (authError.code === 'auth/invalid-password') throw new Error('Password is too weak');
                 throw new Error('Failed to create Auth user');
            }

            // 2.4. Tạo User Document trong Firestore (Dùng transaction)
            const userDocRef = db.collection('users').doc(newUserRecordUid);
            transaction.set(userDocRef, {
                uid: newUserRecordUid, email: email, // Lưu email từ input
                username: lowerCaseUsername, displayName: username,
                bio: '', avatarUrl: `https://placehold.co/120x120?text=${username[0].toUpperCase()}`,
                coverUrl: '', friends: [], blocked: [], needsSetup: false,
                createdAt: admin.firestore.FieldValue.serverTimestamp()
            });

            // 2.5. Tăng bộ đếm IP (Dùng transaction - chỉ tăng nếu có check IP)
            if (normalizedIp) {
                 const ipRef = db.collection('ipRegistrationCounts').doc(normalizedIp);
                 transaction.set(ipRef, { count: admin.firestore.FieldValue.increment(1) }, { merge: true });
            }
        }); // Kết thúc transaction

        // Nếu transaction thành công
        console.log(`User registered successfully: ${username} (UID: ${newUserRecordUid}) from IP ${normalizedIp || 'Unknown'}`);
        // Không cần trả UID về client
        return res.status(200).json({ success: true, message: 'Registration successful!' });

    } catch (error) {
        // Xử lý lỗi từ việc kiểm tra email ban đầu HOẶC từ transaction
        console.error("Registration failed:", error);
        let userMessage = 'Registration failed. Please try again.';
        let statusCode = 500;

        if (error.message === 'IP limit reached') { statusCode = 429; userMessage = 'IP address registration limit reached.'; }
        else if (error.message === 'Email already in use') { statusCode = 409; userMessage = 'Email already in use.'; }
        else if (error.message === 'Username already in use') { statusCode = 409; userMessage = 'Username already in use.'; }
        else if (error.message === 'Password is too weak') { statusCode = 400; userMessage = 'Password must be at least 6 characters.'; }
        else if (error.message === 'Error verifying email availability.') { statusCode = 503; userMessage = 'Could not verify email. Please try again.'; }
        else if (error.message === 'Failed to create Auth user') { userMessage = 'Could not create user account.'; }

        // Cố gắng dọn dẹp Auth user nếu lỡ tạo mà transaction lỗi
        // Quan trọng: Chỉ nên xóa nếu lỗi xảy ra SAU khi đã tạo Auth user thành công
        if (newUserRecordUid && (error.message === 'IP limit reached' || error.message === 'Username already in use' /* || các lỗi Firestore khác */) ) {
             console.warn(`Attempting to delete orphaned Auth user: ${newUserRecordUid}`);
             await auth.deleteUser(newUserRecordUid)
                  .then(() => console.log(`Successfully deleted orphaned Auth user: ${newUserRecordUid}`))
                  .catch(delErr => console.error(`Failed to delete orphaned Auth user ${newUserRecordUid}:`, delErr));
        }

        return res.status(statusCode).json({ error: userMessage });
    }
};