export class UserRegistrationData{
    email!: string
    password!:string
    session!: string
    otp!: string
    name!: string
    role!: string

    constructor(email:string,session: string,otp: string,password: string,name: string,role: string){
        this.email=email
        this.otp=otp
        this.session=session
        this.password=password
        this.name=name
        this.role=role
    }
}

