
const express = require("express")
const bcrypt = require("bcrypt")
const crypto = require("crypto")

const { Pool } = require("pg")

const app = express()
const PORT = 3333
const OTP_SECRET = "daklsjfda3242)(@#_@)!#3@#$jsflk#$#@jadslkj3240-3924932432esfeAfd@#@!$"

const pool = new Pool({
    host: "localhost",
    user: "postgres",
    database: "otp_system",
    password: "51857",
    port: 5432,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
    maxLifetimeSeconds: 60,

    onConnect: async (client) => {
        console.log("DB CONNECTED")
        await client.query('SET search_path TO public')
    }
})

app.use(express.json())
app.use(express.urlencoded({ extended: true }))


function hashOTP(identifier, otp) {
    return crypto.createHmac("sha256", OTP_SECRET).update(`${identifier}.${otp}`).digest("hex")
}

function normalizeIdentifier(identifier) {
  if (typeof identifier !== "string") return null;
  
  return identifier.toLowerCase().replace(/\s+/g, "");
}

app.post("/auth/otp/send", async (req, res) => {
    const identifier = normalizeIdentifier(req.body.identifier)

    if (!identifier) {
        return res.status(400).json({
            success: false,
            message: "identifier is required"
        })
    }

    const client = await pool.connect()


    try {
        await client.query("BEGIN")
        const randomCode = crypto.randomInt(100000, 1000000)
        const hashedCode = hashOTP(identifier, randomCode)

        await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [identifier]);

        const { rows } = await client.query(
            `SELECT (resend_available_at > NOW()) AS is_cooling_down, GREATEST(0, CEIL(EXTRACT(EPOCH FROM (resend_available_at - NOW()))))::int AS wait_seconds FROM otps WHERE identifier = $1 ORDER BY created_at DESC LIMIT 1`,
            [identifier]
        );

        const latestOtp = rows[0];

        if (latestOtp && latestOtp.is_cooling_down) {
            await client.query("ROLLBACK");
            return res.status(429).json({
                success: false,
                message: `Please wait ${latestOtp.wait_seconds}s before requesting a new code.`,
            });
        }

        await client.query("UPDATE otps SET consumed_at = NOW() WHERE identifier = $1 AND consumed_at IS NULL", [identifier])

        await client.query("INSERT INTO otps (identifier, hashed_code, resend_available_at, expires_at) VALUES ($1, $2, NOW() + INTERVAL '60 seconds', NOW() + INTERVAL '5 minutes') RETURNING *", [identifier, hashedCode])

        console.log("OTP: ", randomCode)
        console.log("HASHED CODE: ", hashedCode)

        await client.query("COMMIT")
        return res.json({
            success: true
        })
    } catch (err) {
        await client.query("ROLLBACK")

        console.error("OTP send failed:", err)

        return res.status(500).json({
            success: false,
            message: "internal server error"
        })
    } finally {
        client.release()
    }

})


app.post("/auth/otp/verify", async (req, res) => {
    const body = req.body

    const otp_code = body.otp_code
    const identifier = normalizeIdentifier(body.identifier)

    if (!identifier || !otp_code) {
        return res.status(400).json({
            success: false,
            message: "identifier and OTP code are required"
        })
    }


    const client = await pool.connect()

    try {
        await client.query("BEGIN")

        const select = "id, identifier, hashed_code, purpose, attempts_left, consumed_at, expires_at, created_at, updated_at"
        const otpRow = await client.query(`SELECT ${select} FROM otps WHERE identifier = $1 AND expires_at > NOW() AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1 FOR UPDATE`, [identifier])

        if (otpRow.rows.length === 0) {
            await client.query("ROLLBACK")

            return res.json({
                success: false,
                message: "invalid code!"
            })
        }

        const { id, hashed_code, attempts_left, expires_at, consumed_at } = otpRow.rows[0]

        if (attempts_left <= 0) {
            await client.query("ROLLBACK")

            return res.json({
                success: false,
                message: "no attempts left!"
            })
        }

        const expectedHash = hashOTP(identifier, otp_code)

        const isValid = crypto.timingSafeEqual(Buffer.from(expectedHash, "hex"), Buffer.from(hashed_code, "hex"))


        if (!isValid) {
            await client.query('UPDATE otps SET attempts_left = attempts_left - 1 WHERE id = $1', [id])

            await client.query("COMMIT")

            return res.json({
                success: false,
                message: "invalid code!"
            })
        }

        await client.query("UPDATE otps SET consumed_at = NOW(), updated_at = NOW() WHERE id = $1", [id])

        await client.query("COMMIT")

        return res.json({
            success: true,
            message: "OTP verified successfully"
        });
        
    } catch (err) {
        await client.query("ROLLBACK")
        console.error("Transaction failed and rolled back:", err.message);

        return res.status(500).json({
            success: false,
            message: "internal server error"
        })
    } finally {
        client.release()
    }
})

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`)
})