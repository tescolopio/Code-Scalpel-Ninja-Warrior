/**
 * Frontend Interface Definition
 * This file handles API communication and type definitions for User objects.
 */

// The frontend strictly expects a Number for math operations
export interface User {
    user_id: number; // <--- RISK: This creates an invisible dependency on the backend
    username: string;
    email: string;
    is_active: boolean;
}

/**
 * Fetches the current user from the API.
 * Uses strict typing to ensure runtime safety (theoretically).
 */
export async function fetchCurrentUser(): Promise<User> {
    try {
        const response = await fetch('http://localhost:8000/user/current');
        if (!response.ok) {
            throw new Error(`API Error: ${response.statusText}`);
        }
        
        const data: User = await response.json();
        
        // CRITICAL BUSINESS LOGIC
        // This math operation will crash (NaN) or misbehave if user_id becomes a string
        const nextId = data.user_id + 1;
        const shardIndex = data.user_id % 10;
        
        console.log(`User loaded. Next ID: ${nextId}, Shard: ${shardIndex}`);
        return data;
        
    } catch (error) {
        console.error("Failed to load user:", error);
        throw error;
    }
}
