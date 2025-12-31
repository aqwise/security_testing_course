'use client';

import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useRouter, usePathname } from 'next/navigation';

// SHA-256 hash of the password - change this to your own hash
// Default password: "penetration2026" 
// To generate a new hash, use: console.log(await hashPassword('your-password'))
const VALID_PASSWORD_HASH = '9a8c81274fc39da977d8b2de756e3b062d1d961becd1cbfbb7b43d2a9905bc43'; // 'penetration2026'
const VALID_USERNAME = 'penetration2026';

// Session storage key
const AUTH_KEY = 'security_course_auth';

interface AuthContextType {
    isAuthenticated: boolean;
    isLoading: boolean;
    login: (username: string, password: string) => Promise<boolean>;
    logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Hash password using SHA-256
async function hashPassword(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

export function AuthProvider({ children }: { children: ReactNode }) {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const router = useRouter();
    const pathname = usePathname();

    // Check auth status on mount
    useEffect(() => {
        const checkAuth = () => {
            try {
                const authData = sessionStorage.getItem(AUTH_KEY);
                if (authData) {
                    const { timestamp } = JSON.parse(authData);
                    // Session expires after 24 hours
                    const isValid = Date.now() - timestamp < 24 * 60 * 60 * 1000;
                    setIsAuthenticated(isValid);
                    if (!isValid) {
                        sessionStorage.removeItem(AUTH_KEY);
                    }
                }
            } catch {
                setIsAuthenticated(false);
            }
            setIsLoading(false);
        };

        checkAuth();
    }, []);

    const login = async (username: string, password: string): Promise<boolean> => {
        try {
            const passwordHash = await hashPassword(password);

            if (username === VALID_USERNAME && passwordHash === VALID_PASSWORD_HASH) {
                const authData = {
                    authenticated: true,
                    timestamp: Date.now(),
                };
                sessionStorage.setItem(AUTH_KEY, JSON.stringify(authData));
                setIsAuthenticated(true);
                return true;
            }
            return false;
        } catch {
            return false;
        }
    };

    const logout = () => {
        sessionStorage.removeItem(AUTH_KEY);
        setIsAuthenticated(false);
        router.push('/login');
    };

    return (
        <AuthContext.Provider value={{ isAuthenticated, isLoading, login, logout }}>
            {children}
        </AuthContext.Provider>
    );
}

export function useAuth() {
    const context = useContext(AuthContext);
    if (context === undefined) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
}

// Protected route wrapper component
export function ProtectedRoute({ children }: { children: ReactNode }) {
    const { isAuthenticated, isLoading } = useAuth();
    const router = useRouter();
    const pathname = usePathname();

    useEffect(() => {
        if (!isLoading && !isAuthenticated) {
            // Store the intended destination
            sessionStorage.setItem('redirectAfterLogin', pathname);
            router.push('/login');
        }
    }, [isAuthenticated, isLoading, router, pathname]);

    if (isLoading) {
        return (
            <div className="flex items-center justify-center min-h-[50vh]">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
        );
    }

    if (!isAuthenticated) {
        return null;
    }

    return <>{children}</>;
}
