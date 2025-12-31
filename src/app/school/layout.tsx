'use client';

import { ProtectedRoute } from '@/components/auth/AuthContext';

export default function SchoolLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <ProtectedRoute>
            {children}
        </ProtectedRoute>
    );
}
