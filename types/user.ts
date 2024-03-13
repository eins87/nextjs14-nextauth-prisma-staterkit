export interface User {
  id: number;
  fname: string;
  lname: string;
  email: string;
  picture: string;
  password: string;
  role: {
    id: number;
    name: string;
    description: string;
  };
}