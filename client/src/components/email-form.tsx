

import { useState } from "react";
import { Label } from "./ui/label";
import { Input } from "@base-ui/react/input";
import { Button } from "@base-ui/react/button";

export function EmailForm() {
    const [email, setEmail] = useState("");

    return (
        <div className="grid gap-2">
            <div className="grid gap-1">
                <Label htmlFor="email">Email</Label>
                <Input
                    id="email"
                    type="email"
                    placeholder="m@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                />
            </div>
            <Button type="submit">Send OTP</Button>
        </div>
    )
}
