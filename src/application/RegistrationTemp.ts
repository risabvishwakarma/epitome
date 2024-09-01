
import { UserRegistrationData } from "../models/UserRegistrationData";

export class UserRegistrationMapSingleton {
    getSize(): any {
        console.log(this.userMap.size)
    }
    // Private static instance of the class
    private static instance: UserRegistrationMapSingleton;

    // The map storing user registration data
    private userMap: Map<string, UserRegistrationData>;

    // Private constructor to prevent direct instantiation
    private constructor() {
        this.userMap = new Map<string, UserRegistrationData>();
    }

    // Static method to get the singleton instance
    public static getInstance(): UserRegistrationMapSingleton {
        if (!UserRegistrationMapSingleton.instance) {
            UserRegistrationMapSingleton.instance = new UserRegistrationMapSingleton();
        }
        return UserRegistrationMapSingleton.instance;
    }

    // Save operation with automatic deletion after 1 minute (asynchronous)
    public async save(key: string, data: UserRegistrationData): Promise<void> {
        this.userMap.set(key, data);

        // Set a timeout to delete the entry after 1 minute (60,000 milliseconds)
        await new Promise<void>((resolve) => {
            setTimeout(() => {
                this.userMap.delete(key);
                resolve();
            }, 6000);
        });
    }

    // Find operation to retrieve data by key
    public find(key: string): UserRegistrationData | undefined {
        return this.userMap.get(key);
    }
}
