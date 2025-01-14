import { IsArray, IsOptional, IsString } from "class-validator";

export class OAuthCreateClient {

    @IsString()
    clientId: string;

    @IsString()
    @IsOptional()
    clientSecret: string;

    @IsOptional()
    @IsArray()
    redirectUris?: string[];

    @IsArray()
    grants: string[];
}