"use server"

import { createAuthSession, destroySession } from "@/lib/auth";
import db from "@/lib/db";
import { hashUserPassword, verifyPassword } from "@/lib/hash";
import { createUser } from "@/lib/user";
import { redirect } from "next/navigation";

export async function signup(prevState, formData) {
    const email = formData.get("email")
    const password = formData.get("password")
    let errors = {};

    if (!email.includes('@')) {
        errors.email = "Please Enter a valid Email"
    }
    if (password.trim().length < 8) {
        errors.password = "Password should be at least 8 characters long"
    }

    if (Object.keys(errors).length > 0) {

        return {
            errors: errors
        }


    }
    const hashedPassword = hashUserPassword(password);
    try {

        const id = createUser(email, hashedPassword);
        await createAuthSession(id)

        redirect('/training')
    } catch (error) {
        if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return {
                errors: {
                    email: "Email already exists"
                }
            }
        }
        throw error;
    }


}


export async function login(prevState, formData) {
    const email = formData.get("email")
    const password = formData.get("password")

    const existingUser = await getUserByEmail(email)
    console.log(existingUser);


    if (!existingUser) {
        return {
            errors: {
                email: "Email does not exist"
            }
        }
    }


    const isValidPassword = verifyPassword(existingUser.password, password)
    if (!isValidPassword) {
        return {
            errors: {
                password: "Invalid password"
            }
        }
    }


    await createAuthSession(existingUser.id)

    redirect('/training')


}



export async function auth(mode, prevState, formData) {
    if (mode == 'login') {
        return login(prevState, formData)
    }
    return signup(prevState, formData)
}

export async function getUserByEmail(email) {
    const user = await db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    return user;
}

export async function logout() {
    await destroySession();
    redirect('/')
}