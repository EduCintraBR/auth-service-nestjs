import { IsString } from "class-validator";

export class OAuthAccessTokenIntrospectDto {
    @IsString()
    access_token: string;
}