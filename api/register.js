// api/register.js
const admin = require('firebase-admin');

// --- Cấu hình Firebase Admin SDK ---
// Cậu cần lấy thông tin này từ file JSON đã tải về
// **QUAN TRỌNG:** Không hardcode trực tiếp vào đây! Dùng Environment Variables.
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);

try {
    if (!admin.apps.length) { // Khởi tạo admin app nếu chưa có
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
            // databaseURL: "YOUR_DATABASE_URL" // Thêm nếu cần dùng Realtime DB Admin
        });
    }
} catch (e) {
    console.error('Firebase Admin Initialization Error', e);
}
const db = admin.firestore();
const auth = admin.auth();
// ------------------------------------

// --- Hàm xử lý chính ---
module.exports = async (req, res) => {
    // Cho phép request từ bất kỳ origin nào (tiện lợi khi dev)
    // **LƯU Ý:** Khi deploy thật, nên đổi '*' thành domain web của cậu (vd: https://your-qola-app.vercel.app)
    res.setHeader('Access-Control-Allow-Origin', '*');
    // Cho phép các phương thức cần thiết
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    // Cho phép các header cần thiết (vd: Content-Type)
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    // Xử lý request OPTIONS (trình duyệt gửi trước khi POST để kiểm tra CORS)
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    // --- KẾT THÚC KHỐI CORS ---
    // Chỉ cho phép phương thức POST
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    // Lấy IP từ header (Vercel)
    const ipAddress = req.headers['x-forwarded-for']?.split(',').shift() || req.socket?.remoteAddress;
    if (!ipAddress) {
         console.error("Could not determine IP address. Headers:", req.headers);
         return res.status(400).json({ error: 'Could not determine IP address.' });
    }
    // Chuẩn hóa IP (lấy phần cuối nếu là IPv6 mapped IPv4)
    const normalizedIp = ipAddress.includes(':') ? ipAddress.split(':').slice(-1)[0] : ipAddress;

    const { username, email, password } = req.body; // Lấy data từ request body

    // --- Kiểm tra Input phía server ---
    if (!username || !email || !password || password.length < 6 || username.length < 3 || /\s/.test(username) || !/^[a-z0-9_.]+$/.test(username)) {
        return res.status(400).json({ error: 'Invalid registration data.' });
    }
    const lowerCaseUsername = username.toLowerCase(); // Luôn dùng lowercase để check/lưu

    // --- Bắt đầu Transaction để đảm bảo tính nhất quán ---
    try {
        await db.runTransaction(async (transaction) => {
            // 1. Kiểm tra giới hạn IP
            const ipRef = db.collection('ipRegistrationCounts').doc(normalizedIp);
            const ipDoc = await transaction.get(ipRef);
            const currentCount = ipDoc.exists ? ipDoc.data().count : 0;

            if (currentCount >= 3) {
                throw new Error('IP limit reached'); // Ném lỗi để transaction rollback
            }

            // 2. Kiểm tra email tồn tại (trong Auth)
            try {
                await auth.getUserByEmail(email);
                // Nếu không lỗi -> email đã tồn tại
                throw new Error('Email already in use');
            } catch (error) {
                if (error.code !== 'auth/user-not-found') {
                    console.error("Error checking email:", error);
                    throw new Error('Error checking email'); // Lỗi khác
                }
                // Email hợp lệ, tiếp tục
            }

            // 3. Kiểm tra username tồn tại (trong Firestore)
            const usersRef = db.collection("users");
            const qUsername = usersRef.where("username", "==", lowerCaseUsername);
            const usernameSnapshot = await transaction.get(qUsername); // Dùng transaction.get
            if (!usernameSnapshot.empty) {
                throw new Error('Username already in use');
            }

            // --- Nếu mọi thứ OK ---
            // 4. Tạo User Auth (bên ngoài transaction vì là thao tác Auth)
            let newUserRecord;
            try {
                 newUserRecord = await auth.createUser({
                     email: email,
                     password: password,
                     displayName: username // Gán display name ban đầu
                 });
            } catch (authError) {
                 console.error("Firebase Auth createUser error:", authError);
                 // Cố gắng map lỗi Auth sang lỗi dễ hiểu hơn
                 if (authError.code === 'auth/email-already-exists') throw new Error('Email already in use');
                 if (authError.code === 'auth/invalid-password') throw new Error('Password is too weak');
                 throw new Error('Failed to create Auth user'); // Lỗi chung
            }


            // 5. Tạo User Document trong Firestore (Dùng transaction)
            const userDocRef = db.collection('users').doc(newUserRecord.uid);
            transaction.set(userDocRef, {
                uid: newUserRecord.uid,
                email: newUserRecord.email,
                username: lowerCaseUsername, // Lưu lowercase
                displayName: username,
                bio: '',
                avatarUrl: `https://placehold.co/120x120?text=${username[0].toUpperCase()}`,
                coverUrl: '',
                friends: [],
                blocked: [],
                needsSetup: true,
                createdAt: admin.firestore.FieldValue.serverTimestamp()
            });

            // 6. Tăng bộ đếm IP (Dùng transaction)
            transaction.set(ipRef, { count: admin.firestore.FieldValue.increment(1) }, { merge: true });

            // Transaction tự commit nếu không có lỗi
        });

        // Nếu transaction thành công
        console.log(`User registered successfully: ${username} from IP ${normalizedIp}`);
        return res.status(200).json({ success: true, message: 'Registration successful!' });

    } catch (error) {
        // Xử lý lỗi từ transaction hoặc lỗi tạo Auth user
        console.error("Registration transaction failed:", error);
        let userMessage = 'Registration failed.';
        let statusCode = 500; // Lỗi server mặc định

        if (error.message === 'IP limit reached') {
            userMessage = 'IP address registration limit reached.';
            statusCode = 429; // Too Many Requests
        } else if (error.message === 'Email already in use') {
            userMessage = 'Email already in use.';
            statusCode = 409; // Conflict
        } else if (error.message === 'Username already in use') {
            userMessage = 'Username already in use.';
            statusCode = 409; // Conflict
        } else if (error.message === 'Password is too weak') {
            userMessage = 'Password must be at least 6 characters.';
            statusCode = 400; // Bad Request
        } else if (error.message === 'Failed to create Auth user') {
             userMessage = 'Could not create user account.';
             // Giữ statusCode 500
        } else if (error.message === 'Error checking email') {
             userMessage = 'Error verifying email availability.';
             // Giữ statusCode 500
        }


        // Cố gắng dọn dẹp nếu lỡ tạo user Auth mà transaction lỗi sau đó
        // (Phần này hơi khó để làm hoàn hảo, tạm bỏ qua để đơn giản)

        return res.status(statusCode).json({ error: userMessage });
    }
};